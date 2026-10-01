// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Packet Capture (Receive Path)
//!
//! The single ingest path for raw scan replies, shared by every send backend.
//!
//! BSD-derived kernels, macOS included, do not deliver TCP or UDP segments to raw IP
//! sockets, so the Layer-4 raw socket that works on Linux receives nothing there.
//! Capturing at the data-link layer via `libpcap` avoids that: BPF (macOS/BSD),
//! `AF_PACKET` (Linux) and Npcap (Windows) all see inbound frames before the stack
//! handles them, so one capture path behaves the same everywhere.
//!
//! Each interface is opened with a compiled BPF filter so the kernel drops everything
//! except the packets a scan cares about; only matching frames are copied into
//! userspace. Captures run on dedicated OS threads (the `libpcap` read blocks) and
//! funnel parsed segments into a single Tokio channel, so async scan code consumes one
//! merged stream however many interfaces are live.
//!
//! [`CaptureOptions`] describes a capture. Which frames the kernel admits, how much of
//! each it keeps, and whether it accepts traffic addressed elsewhere have to be chosen
//! together, and [`CaptureOptions::for_replies`] is the choice a scanner should take
//! unchanged.

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcap::{Active, Capture};
#[cfg(not(windows))]
use std::os::unix::io::AsRawFd;
use tokio::sync::mpsc;

use crate::logging::error;
use crate::model::capture::{CaptureCounts, IpObservation};
use crate::model::ip::scoped::Zone;
use crate::model::mac::MacAddr;
use crate::protocols::ethernet::VLAN_TAG_LEN;
use crate::protocols::sizes::{ETH_HDR_LEN, IP_V6_HDR_LEN};
use crate::system::descriptors::Descriptor;
use crate::transport::frame::{self, LinkType};
use crate::{counted, info, warn};

/// How much of each frame a scan's receive path keeps: a whole frame at Ethernet's
/// standard MTU, behind the deepest link header this crate strips.
///
/// Sized to the largest thing a reader of these captures reads whole. A probe's answer
/// is a few headers; an ICMP error quotes at most 576 bytes over IPv4 (RFC 1812) and
/// 1,280 over IPv6 (RFC 4443); a UDP answer is read for a DNS header or a NetBIOS name
/// table; and the DNS and mDNS answers the resolver sniffs, like the ARP, neighbour
/// discovery, LLDP and CDP frames a segment sweep reads, are single frames on a
/// standard link. Only jumbo frames, loopback and segments coalesced by interface
/// offloads are longer, and of those a reader gets the headers and the start of the
/// payload.
///
/// No larger, because on Linux the capture's ring is counted in snapshot lengths. In
/// immediate mode `libpcap` reads through a ring of fixed slots, one frame per slot,
/// each sized from the snapshot length; the link's MTU caps it only on an interface
/// without segmentation offloads, which veth pairs and most server adapters are not.
/// At `libpcap`'s default two-megabyte buffer this length makes 1,310 slots of 1,600
/// bytes, where 65,535 makes 32. A port probe costs up to three frames: the probe
/// leaving, its answer, and the reset the kernel sends to an unsolicited SYN-ACK.
/// Thirty-two slots overflow within a scan's first window, and every dropped answer is
/// a port asked again and a congestion window halved on a host that answered.
pub const REPLY_SNAP_LEN: u32 = (ETH_HDR_LEN + 2 * VLAN_TAG_LEN + ETHERNET_MTU) as u32;

/// The largest IP packet a standard Ethernet link carries in one frame (IEEE 802.3).
const ETHERNET_MTU: usize = 1_500;

/// The shortest snapshot length worth opening a capture at.
///
/// The deepest header stack this crate reads before it has an answer: an Ethernet
/// header with two VLAN tags, the larger of the two IP headers, and a TCP header with
/// full options. A capture snapped below that truncates the reply it was opened for and
/// reports the result as silence. Every other link header this crate strips is shorter
/// than the tagged Ethernet one.
///
/// A floor, not a default. [`CaptureOptions::with_snaplen`] raises anything lower to
/// it, which also keeps a zero from reaching `libpcap`, whose manual leaves that value
/// undefined.
pub const MIN_SNAP_LEN: u32 =
    (ETH_HDR_LEN + 2 * VLAN_TAG_LEN + IP_V6_HDR_LEN + TCP_MAX_HDR_LEN) as u32;

/// A TCP header with the full forty bytes of options its data offset can describe.
const TCP_MAX_HDR_LEN: usize = 60;

// The floor's argument, checked at compile time since every side of it is a constant.
const _: () = assert!(
    MIN_SNAP_LEN as usize >= ETH_HDR_LEN + 2 * VLAN_TAG_LEN + IP_V6_HDR_LEN + TCP_MAX_HDR_LEN,
    "the snapshot floor is below a header stack this crate parses"
);
const _: () = assert!(
    REPLY_SNAP_LEN > MIN_SNAP_LEN,
    "the snapshot length a scanner takes unchanged is below the floor"
);
const _: () = assert!(
    frame::SLL_HDR_LEN <= ETH_HDR_LEN + 2 * VLAN_TAG_LEN
        && frame::SLL2_HDR_LEN <= ETH_HDR_LEN + 2 * VLAN_TAG_LEN,
    "a cooked link header is deeper than the one the snapshot floor was sized for"
);

/// How a capture is opened: what the kernel admits, how much of each frame it keeps,
/// and whose traffic it accepts.
///
/// [`for_replies`](Self::for_replies) is the setting for a scan's receive path, and a
/// scanner should take it unchanged. The builders are for callers reading traffic the
/// scan did not cause, whose needs differ on every setting here.
///
/// The settings are not independent: a wide filter with a generous snapshot length
/// and a default buffer is a capture that discards most of what it admits. So they are
/// chosen together, as one value.
///
/// The snapshot length is also the one limit on how much of other people's traffic
/// this process reads that the kernel enforces.
#[must_use]
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// What the kernel admits, compiled for each link to a BPF program. Only matching
    /// frames are copied into this process.
    filter: CaptureFilter,
    /// How many bytes of each matching frame to keep. The kernel discards the rest.
    snaplen: u32,
    /// Whether to accept frames not addressed to this host.
    promiscuous: bool,
    /// How much the kernel may hold for this capture before it starts discarding.
    /// `None` leaves `libpcap`'s default in place.
    buffer_bytes: Option<u32>,
}

impl CaptureOptions {
    /// A capture of what was addressed to this host: the replies to probes it sent.
    ///
    /// Not promiscuous, unlike [`for_link_traffic`](Self::for_link_traffic). Replies
    /// come back to this host, so frames addressed elsewhere would only be other
    /// people's traffic, filling the buffer this scan's answers must fit in.
    ///
    /// Keeps a whole frame at Ethernet's standard MTU ([`REPLY_SNAP_LEN`]): everything
    /// a reply is read for, and short enough that Linux's ring, whose slots are sized
    /// from it, holds a scan's bursts.
    ///
    /// The platform's default buffer, since the snapshot length decides how many
    /// replies fit. On Linux the default two megabytes hold 1,310 frames, about twenty
    /// milliseconds of arrivals at the 20,000 probes a second a full-range scan reaches
    /// over a veth pair, so the reader must fall behind by a scheduling delay, not a
    /// round trip, before anything is lost; such a scan drops nothing whether the
    /// processors are busy or idle. macOS's BPF and Windows' Npcap count their buffers
    /// in bytes (a small header per frame plus what was kept), and their defaults, half
    /// a megabyte and one, hold thousands of replies a few dozen bytes long. A larger
    /// buffer would also buy Linux slots, but a capture is opened on every link that is
    /// up, so its size is paid per link on every open, while the snapshot length costs
    /// nothing.
    pub fn for_replies(filter: impl Into<CaptureFilter>) -> Self {
        Self {
            filter: filter.into(),
            snaplen: REPLY_SNAP_LEN,
            promiscuous: false,
            buffer_bytes: None,
        }
    }

    /// A capture of everything the link carries that `filter` admits, whoever it was
    /// addressed to.
    ///
    /// Promiscuous, unlike [`for_replies`](Self::for_replies), because several things
    /// a segment sweep concludes arrive in frames addressed to someone else: a DHCP
    /// server's answer is often unicast to the client that asked, and the interface may
    /// filter out a multicast group this host never joined before `libpcap` sees it.
    ///
    /// `filter` does the narrowing, in the kernel: promiscuity decides what the
    /// interface hands up, the filter decides what is copied into this process.
    pub fn for_link_traffic(filter: impl Into<CaptureFilter>) -> Self {
        Self {
            promiscuous: true,
            ..Self::for_replies(filter)
        }
    }

    /// Keeps only the first `bytes` of each frame, discarding the rest in the kernel.
    ///
    /// Bounds both the copying a busy link costs this process and how much of a payload
    /// it has no business reading it can see, a limit the kernel enforces.
    ///
    /// Raised to [`MIN_SNAP_LEN`] where lower, since below that a capture cannot see
    /// the headers it exists to read. `libpcap` leaves a snapshot length of zero
    /// undefined and its meaning has varied across versions, so it is never passed.
    pub fn with_snaplen(mut self, bytes: u32) -> Self {
        self.snaplen = bytes.max(MIN_SNAP_LEN);
        self
    }

    /// Accepts frames not addressed to this host, which the interface would otherwise
    /// discard before `libpcap` saw them.
    ///
    /// On a switched network this admits broadcast and multicast in full and unicast
    /// only where the switch forwards it, so it widens what *can* be seen without
    /// promising anything will be.
    pub fn with_promiscuous(mut self, promiscuous: bool) -> Self {
        self.promiscuous = promiscuous;
        self
    }

    /// Lets the kernel hold `bytes` for this capture before it starts discarding.
    ///
    /// The buffer absorbs the gap between a burst arriving and this process reading
    /// it, so it decides whether a spike becomes a `dropped` count. Worth raising for
    /// any capture whose arrival rate the network sets, not this host's probes. On
    /// Linux it is counted in slots sized from the snapshot length, so the two settings
    /// decide it together; see [`REPLY_SNAP_LEN`].
    pub fn with_buffer_bytes(mut self, bytes: u32) -> Self {
        self.buffer_bytes = Some(bytes);
        self
    }
}

/// What a capture admits, in `libpcap`'s filter syntax, the syntax `tcpdump` takes.
///
/// Two shapes, because a filter is compiled once per link and links differ in what
/// they can express. An [`expression`](Self::expression) is compiled as written, and a
/// link that cannot compile it is not captured on. A set of alternatives,
/// [`any_of`](Self::any_of), admits a frame any one of them admits; each link compiles
/// the ones it can express and leaves the rest out.
///
/// # When leaving a clause out is sound
///
/// A clause a link cannot express names something the link does not carry. `ether
/// dst` names a hardware address, and a tunnel, a PPP link or a loopback without an
/// Ethernet header has none, so `libpcap` refuses to compile it there: no frame on that
/// link could have matched. Leaving it out loses nothing, while refusing the whole
/// filter would lose everything the other clauses admit, on a tunnel every IP packet.
///
/// That holds for a clause the link cannot express, not for one nothing can: a typo
/// should not be silently dropped. So a clause a link refuses is compiled again for
/// Ethernet, the link that expresses the most, and only left out if that succeeds.
/// Otherwise the capture fails with [`CaptureError::Filter`] naming it.
///
/// Alternatives suit a capture reading several unrelated kinds of traffic, as a
/// listener does. A scan's reply filter is an expression, since every part is needed
/// for the scan to hear its answers, and a link that can express only some of it is
/// refused and reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFilter {
    shape: FilterShape,
}

/// The two shapes a [`CaptureFilter`] takes, private so a filter is built through the
/// constructors that say which one is meant.
#[derive(Debug, Clone, PartialEq, Eq)]
enum FilterShape {
    /// Compiled as written, on every link or on none.
    Expression(String),
    /// Joined by `or`, each link taking the clauses it can express.
    AnyOf(Vec<String>),
}

impl CaptureFilter {
    /// A filter compiled as written, on every link or on none.
    pub fn expression(expression: impl Into<String>) -> Self {
        Self {
            shape: FilterShape::Expression(expression.into()),
        }
    }

    /// A filter admitting a frame any of `clauses` admits, each link taking the
    /// clauses it can express.
    ///
    /// Each clause is a complete expression, joined to the others by `or`, so it must
    /// parenthesise anything that would not survive that.
    pub fn any_of<I, S>(clauses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            shape: FilterShape::AnyOf(clauses.into_iter().map(Into::into).collect()),
        }
    }

    /// The expression to compile on the link `capture` is open on, with the clauses
    /// that link cannot express left out.
    ///
    /// Asks `libpcap` through the capture itself: which clauses a data-link type can
    /// express is `libpcap`'s knowledge, and a table here would be a second copy that
    /// could drift.
    pub(crate) fn for_link<T: pcap::Activated + ?Sized>(
        &self,
        capture: &Capture<T>,
    ) -> Result<(String, Vec<String>), CaptureError> {
        let clauses = match &self.shape {
            FilterShape::Expression(expression) => return Ok((expression.clone(), Vec::new())),
            FilterShape::AnyOf(clauses) => clauses,
        };

        let mut kept = Vec::new();
        let mut left_out = Vec::new();
        let mut refused = None;
        for clause in clauses {
            match capture.compile(clause, true) {
                Ok(_) => kept.push(clause.as_str()),
                Err(source) => {
                    if let Err(malformed) = compiles_for_ethernet(clause) {
                        return Err(CaptureError::Filter {
                            filter: clause.clone(),
                            source: LibraryError::new(malformed),
                        });
                    }
                    left_out.push(clause.clone());
                    refused = Some(source);
                }
            }
        }

        match refused {
            Some(source) if kept.is_empty() => Err(CaptureError::Filter {
                filter: self.to_string(),
                source: LibraryError::new(source),
            }),
            _ => Ok((kept.join(" or "), left_out)),
        }
    }
}

/// Whether `clause` compiles for Ethernet, the link expressing the most, and what
/// `libpcap` said where it does not.
///
/// Uses a dead handle with no device behind it: compiling needs only a link type, so
/// this asks nothing of the host and needs no privilege.
fn compiles_for_ethernet(clause: &str) -> Result<(), pcap::Error> {
    Capture::dead(pcap::Linktype::ETHERNET)?.compile(clause, true)?;
    Ok(())
}

impl std::fmt::Display for CaptureFilter {
    /// The filter as written, every alternative included.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.shape {
            FilterShape::Expression(expression) => f.write_str(expression),
            FilterShape::AnyOf(clauses) => f.write_str(&clauses.join(" or ")),
        }
    }
}

impl From<String> for CaptureFilter {
    fn from(expression: String) -> Self {
        Self::expression(expression)
    }
}

impl From<&str> for CaptureFilter {
    fn from(expression: &str) -> Self {
        Self::expression(expression)
    }
}

/// How long a reader thread waits for a frame before checking the stop flag again.
/// Bounds shutdown latency without busy-looping.
///
/// On Unix this is the timeout of the [`wait_readable`] poll, since `libpcap`'s own
/// read timeout cannot be relied on: see [`open`].
const READ_TIMEOUT_MS: i32 = 100;

/// How many frames a reader may forward between refreshes of its kernel counters.
///
/// A scanner reads [`CaptureCounts`] while its capture threads are running, so the
/// counters must be current mid-run. Refreshing only when idle would miss the case
/// worth measuring: while frames arrive faster than they are read the loop never goes
/// idle, and that is when a buffer overflows.
const STATS_EVERY_FRAMES: u32 = 128;

/// How long a reader thread waits before offering a frame again once the consumer's
/// queue is full.
///
/// Short enough not to hold up a consumer catching up, long enough that an overrun
/// capture does not spin a core while the kernel buffer absorbs the burst.
const QUEUE_FULL_PAUSE: Duration = Duration::from_millis(1);

/// One reply lifted off the wire: the Layer-4 segment, who sent it, which protocol it
/// is, and what its IP header said.
///
/// The protocol is carried because a filter may admit more than one (a UDP port scan
/// watches for direct UDP replies and the ICMP errors that answer them), and Layer-4
/// headers cannot be told apart after the fact (see [`frame::IpSegment`]).
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedSegment {
    /// The address the segment came from.
    pub source: IpAddr,
    /// The address it was going to, so a capture admitting both directions can tell a
    /// scan's own probe from the answer to it. `None` for a synthetic stream with no
    /// IP header, as [`observation`](Self::observation) is.
    pub destination: Option<IpAddr>,
    /// The protocol [`bytes`](Self::bytes) should be parsed as, by its IANA number: 6
    /// for TCP, 17 for UDP, 58 for ICMPv6.
    pub protocol: u8,
    /// The Layer-4 segment, link and IP headers already stripped.
    pub bytes: Vec<u8>,
    /// What the IP header this segment arrived under said about the stack that sent
    /// it, or `None` if there was no IP header.
    ///
    /// `None` means the segment did not come off a wire: a synthetic receive stream
    /// built through `ProbeTransport::from_parts` hands over Layer-4 bytes it composed
    /// itself. Reporting a default TTL and zero identifier for one would claim a
    /// measurement nobody took, which is also why
    /// [`CaptureGuard::counts`](CaptureGuard::counts) is optional. A test exercising
    /// something that reads these must supply one explicitly.
    pub observation: Option<IpObservation>,

    /// The hardware address the frame carrying this segment came from, where the link
    /// had one.
    ///
    /// The only thing here that can say whether a reply came from the host it claims
    /// to. Anything answering in a host's place uses that host's IP address, so
    /// [`source`](Self::source) cannot tell a genuine answer from an intercepted one;
    /// this can, on an on-link segment.
    ///
    /// Not for vendor lookup: an off-link reply carries the last-hop router's address.
    /// See [`frame::source_mac`].
    ///
    /// `None` on a tunnel, PPP, loopback or raw-IP link, which carry no hardware
    /// address, and on a synthetic stream. It does not mean the sender had none.
    pub source_mac: Option<MacAddr>,

    /// When the capture thread took delivery of this segment.
    ///
    /// The earliest monotonic point in the pipeline, taken in the `libpcap` callback
    /// before the segment is queued. A round trip measured from dequeue time would
    /// include the channel's depth and the runtime's scheduling, which on a fast link
    /// is most of it: 4.5 ms of pipeline over a 0.1 ms path.
    ///
    /// Monotonic, unlike the kernel's wall-clock frame timestamp, which
    /// [`CapturedFrame::observed_at`] carries for readers that place a finding on a
    /// timeline. A duration needs a clock that cannot be adjusted underneath it.
    pub received_at: Instant,
}

impl CapturedSegment {
    /// A segment with no IP header behind it, for a receive stream that composed its
    /// Layer-4 bytes.
    ///
    /// The way to build a segment outside this crate, so adding a field does not break
    /// every synthetic transport. Set anything beyond the bytes, such as a destination
    /// or an observed header, on the result.
    pub fn synthetic(source: IpAddr, protocol: u8, bytes: Vec<u8>) -> Self {
        Self {
            source,
            destination: None,
            protocol,
            bytes,
            observation: None,
            received_at: Instant::now(),
            source_mac: None,
        }
    }
}

/// The parsed receive stream of a running capture: [`CapturedSegment`]s from every
/// captured interface, interleaved in arrival order.
///
/// Bounded, like [`FrameStream`] and for the same reason. [`segments`] documents where
/// the traffic that fills it comes from.
pub type CaptureStream = mpsc::Receiver<CapturedSegment>;

/// One frame as it came off a link, with nothing stripped.
///
/// The counterpart to [`CapturedSegment`], for answers outside a Layer-4 segment. An
/// ARP exchange, a neighbour advertisement, a switch announcing itself and an 802.1Q
/// tag all live below where [`CapturedSegment`] begins, and are gone by the time one
/// exists.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// The link this frame arrived on.
    ///
    /// Much of what a frame proves holds only on one segment. An IPv6 link-local
    /// address names a different machine on every link, a switch announces itself to
    /// the port it is announcing *about*, and a VLAN tag means nothing without the
    /// trunk it was read from. A capture merges every link into one stream, so this
    /// keeps the merge lossless.
    pub zone: Zone,

    /// How [`bytes`](Self::bytes) is framed, so a reader knows what it is looking at.
    pub link: LinkType,

    /// The frame, link header included.
    ///
    /// Possibly truncated to the [`CaptureOptions::with_snaplen`] the capture was opened
    /// with, which limits how much of other people's traffic is read. A reader treats a
    /// short frame as ordinary, not corrupt; every parser in [`crate::protocols`]
    /// declines on short input.
    pub bytes: Vec<u8>,

    /// When the kernel timestamped the frame.
    pub observed_at: SystemTime,

    /// When the capture thread took delivery of this frame, on the monotonic clock a
    /// round trip is measured against.
    ///
    /// The frame-stream twin of [`CapturedSegment::received_at`]: a sweep reading
    /// replies as frames times each one from here, so queue depth and runtime
    /// scheduling stay out of its round trips. [`observed_at`](Self::observed_at) is
    /// earlier but on a clock that can be stepped, so it places a frame on a timeline
    /// and this one times it.
    pub received_at: Instant,
}

impl CapturedFrame {
    /// A frame lifted off `zone` just now, framed as `link` says.
    pub fn new(zone: Zone, link: LinkType, bytes: Vec<u8>) -> Self {
        Self {
            zone,
            link,
            bytes,
            observed_at: SystemTime::now(),
            received_at: Instant::now(),
        }
    }
}

/// The whole-frame receive stream produced by [`frames`]: [`CapturedFrame`]s from
/// every captured link, interleaved in arrival order.
///
/// Bounded, unlike [`CaptureStream`]. The network, not this host's probes, sets the
/// arrival rate, so the consumer is not guaranteed to keep up, and an unbounded queue
/// would grow until the process died. [`frames`] documents what happens instead.
pub type FrameStream = mpsc::Receiver<CapturedFrame>;

/// One capture's counters, written by its reader thread and read by whoever holds the
/// [`CaptureGuard`].
///
/// Atomics, because the writer is a capture thread in its hot loop: a slightly stale
/// count leads a reader to the same conclusion, while a lock in that loop would perturb
/// the timing being measured.
#[derive(Debug, Default)]
struct CaptureStats {
    received: AtomicU64,
    dropped: AtomicU64,
    if_dropped: AtomicU64,
    /// Whether this reader ended before it was told to.
    ///
    /// A flag here and a count in [`CaptureCounts`]: one capture either lasted or not,
    /// and a report wants to know how many did.
    stopped_early: AtomicBool,
}

impl CaptureStats {
    /// Replaces the counters with what `libpcap` currently reports. The values are
    /// cumulative from the start of the capture, so they are stored, not added.
    fn store(&self, stat: &pcap::Stat) {
        self.received.store(stat.received as u64, Ordering::Relaxed);
        self.dropped.store(stat.dropped as u64, Ordering::Relaxed);
        self.if_dropped
            .store(stat.if_dropped as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> CaptureCounts {
        CaptureCounts {
            received: self.received.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            if_dropped: self.if_dropped.load(Ordering::Relaxed),
            stopped_early: u64::from(self.stopped_early.load(Ordering::Relaxed)),
        }
    }
}

/// Keeps a set of live per-interface captures running while held. Dropping it signals
/// every reader thread to stop and waits for each, so no capture thread outlives the
/// guard.
///
/// Dropping blocks for up to one read timeout, bounded by the stop flag. A thread
/// waiting for room in a full queue also checks the flag, so a guard dropped while a
/// consumer holds the receiver without draining it returns on the same schedule.
///
/// A guard is normally dropped inside the scan task, on a runtime worker, so on a
/// multi-threaded runtime the wait goes through
/// [`block_in_place`](tokio::task::block_in_place) and the worker is free for other
/// tasks meanwhile. A single-threaded runtime has no other worker, and a caller outside
/// a runtime blocks its own thread.
///
/// Separate from the [`CaptureStream`] it feeds, so a consumer can own the receiver
/// (borrowing it mutably in a `select!`) while the guard keeps the threads alive
/// beside it.
pub struct CaptureGuard {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    /// One set of counters per live capture, shared with the thread reading it.
    stats: Vec<Arc<CaptureStats>>,
    /// The permits the descriptor gate has no socket for once these captures' links
    /// are open, held out of it while they are. See [`running`](Self::running).
    _held_back: Option<Descriptor>,
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);

        // A reader that panicked has already marked its capture and logged it as it
        // unwound; see `spawn_reader`. Only the wait is left.
        let handles = std::mem::take(&mut self.handles);
        let wait = move || {
            for handle in handles {
                let _ = handle.join();
            }
        };

        match tokio::runtime::Handle::try_current().map(|handle| handle.runtime_flavor()) {
            Ok(tokio::runtime::RuntimeFlavor::MultiThread) => tokio::task::block_in_place(wait),
            _ => wait(),
        }
    }
}

impl CaptureGuard {
    /// A guard owning no capture threads, for a transport whose receive stream is
    /// supplied directly. Reached from outside the crate only through
    /// [`ProbeTransport::from_parts`].
    ///
    /// [`ProbeTransport::from_parts`]: crate::transport::probe::ProbeTransport::from_parts
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn noop() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
            stats: Vec::new(),
            _held_back: None,
        }
    }

    /// A guard over one capture that already stopped early, with no thread behind it.
    #[cfg(test)]
    pub(crate) fn stopped_early() -> Self {
        let counters = CaptureStats::default();
        counters.stopped_early.store(true, Ordering::Relaxed);
        Self {
            stop: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
            stats: vec![Arc::new(counters)],
            _held_back: None,
        }
    }

    /// A guard over the reader threads `handles`, whose links are open, taking out of
    /// the descriptor gate what the table no longer has a socket for.
    ///
    /// A capture holds a descriptor per link it listens on, thirty on a laptop with a
    /// VPN and a hypervisor, and every transport opens its own. A scan's connection
    /// budget was read off the table when the scan started, before these were open, so
    /// without this the connections are promised sockets the captures hold, and each
    /// one past the table's room waits out its patience and is filed unasked. Read here,
    /// after the links are open, the table counts them, and the permits return to the
    /// gate when the captures close. See
    /// [`hold_back`](crate::system::descriptors::hold_back).
    fn running(
        stop: Arc<AtomicBool>,
        handles: Vec<JoinHandle<()>>,
        stats: Vec<Arc<CaptureStats>>,
    ) -> Self {
        Self {
            stop,
            handles,
            stats,
            _held_back: crate::system::descriptors::hold_back(),
        }
    }

    /// The kernel counters of every capture this guard keeps alive, summed.
    ///
    /// `None` when there is no capture: a transport fed a synthetic receive stream has
    /// no kernel buffer, and reporting zero drops would claim a measurement nobody
    /// took.
    pub fn counts(&self) -> Option<CaptureCounts> {
        if self.stats.is_empty() {
            return None;
        }

        Some(
            self.stats
                .iter()
                .map(|stats| stats.snapshot())
                .fold(CaptureCounts::default(), |total, counts| total + counts),
        )
    }
}

/// Why a capture could not be started.
///
/// An interface that cannot be captured is skipped and logged: a host has several,
/// most irrelevant to a given probe, and a virtual bridge declining should not stop a
/// scan. Only every interface failing leaves nowhere to hear an answer, and that is
/// [`NoInterface`](Self::NoInterface), which carries each link's own refusal.
///
/// Privilege is one cause among several and is named only where it is the cause. A
/// root process can be refused a capture by a filter the link cannot express, a
/// framing nothing here parses, or an adapter the capture driver will not bind, and
/// blaming privilege for those misleads someone who already has it.
/// [`is_denied`](Self::is_denied) is the question to ask.
///
/// `#[non_exhaustive]` because new platform-specific failures show up first in the
/// capture layer.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// No link could be captured on, so nothing could be heard.
    ///
    /// Carries every link's refusal, since they need not agree and the reason is what
    /// there is to act on. Where every one was [`Denied`](Self::Denied) the message
    /// says so in one sentence, the ordinary case of an unprivileged process; otherwise
    /// it gives each reason once, naming the link where one link gave it and counting
    /// them where several did.
    #[error(
        "no link could be captured on, so nothing could be heard: {}",
        refusals_reason(refused)
    )]
    NoInterface {
        /// Each link tried, by name, and why it could not be captured on, in the order
        /// tried.
        refused: Vec<(String, CaptureError)>,
    },
    /// Every link opened and none could be given a reader thread.
    ///
    /// A runtime condition: a process near its thread limit, or a cgroup capping them.
    /// Separate from [`NoInterface`](Self::NoInterface) because the remedy differs and
    /// has nothing to do with privilege.
    #[error(
        "captured {} but could not start a reader for any of them: {source}",
        crate::logging::counted(*opened as u128, "link", "links")
    )]
    NoReader {
        /// How many links opened before the threads were asked for.
        opened: usize,
        /// What the last spawn refused with.
        #[source]
        source: std::io::Error,
    },
    /// A link carries frames this crate cannot strip down to an IP packet.
    ///
    /// The capture came up, but its data-link type is one nothing here parses. Skipped,
    /// since guessing at a framing would report a network that is not there.
    #[error("{interface} carries data-link type {dlt}, which nothing here parses")]
    UnsupportedLinkType {
        /// The link that was opened.
        interface: String,
        /// The `libpcap` data-link type it reported.
        dlt: i32,
    },

    /// The filter expression would not compile to a BPF program.
    ///
    /// Either a mistake in the expression or a link that cannot express it: an
    /// Ethernet address means nothing on a tunnel, and `libpcap` refuses to compile one
    /// for it. Either way the expression is what to look at, so it is named.
    #[error("the filter `{filter}` would not compile: {source}")]
    Filter {
        /// The expression that was rejected.
        filter: String,
        /// What `libpcap` said.
        #[source]
        source: LibraryError,
    },

    /// One named link could not be opened, for a reason other than privilege. Unlike
    /// `NoInterface` this names the link, because the caller asked for that one and
    /// there is nothing to fall back to.
    #[error("{interface} could not be opened: {source}")]
    Open {
        /// The link that refused.
        interface: String,
        /// What `libpcap` said.
        #[source]
        source: LibraryError,
    },

    /// One named link could not be opened because this process may not capture on it.
    ///
    /// Separate from [`Open`](Self::Open) because its remedy lies outside the link:
    /// root, or whatever grants the right to capture short of it, such as membership
    /// of `access_bpf` on macOS or `cap_net_raw` on Linux. Decided by the status
    /// `libpcap` activated the handle with, not by its message.
    #[error("{interface} could not be opened without privileges this process lacks: {source}")]
    Denied {
        /// The link that refused.
        interface: String,
        /// What `libpcap` said.
        #[source]
        source: LibraryError,
    },

    /// The process or the system ran out of descriptors partway through the links, so
    /// a capture would have been deaf on the links it did not reach.
    ///
    /// Not skipped like a link that declines. A declining link is one the scan's
    /// targets do not answer through; these are refused for a local shortage, and any
    /// of them may be where the replies arrive. Heard on the rest alone, those replies
    /// would read as targets that did not answer.
    #[error(
        "no capture on {} (file limit reached)",
        crate::logging::counted(links.len() as u128, "link", "links")
    )]
    OutOfDescriptors {
        /// The links refused a capture, by name, in the order they were tried.
        links: Vec<String>,
    },
}

impl CaptureError {
    /// Whether this failure is a missing privilege and nothing else.
    ///
    /// True of a link that [`Denied`](Self::Denied) this process, and of a capture
    /// with no link because every link did. A capture refused on other grounds, even
    /// alongside links that denied it, answers false: the privilege would not have
    /// made it work.
    pub fn is_denied(&self) -> bool {
        match self {
            Self::Denied { .. } => true,
            Self::NoInterface { refused } => {
                !refused.is_empty() && refused.iter().all(|(_, error)| error.is_denied())
            }
            _ => false,
        }
    }

    /// Whether this is one link refused because no descriptor was left to open its
    /// capture with.
    ///
    /// Read from the library's words, since `libpcap` reports the shortage under the
    /// same status as any other failure to open a device. Those words are the C
    /// library's own text for the errno, the same this process's own errors carry, so
    /// the match is against that.
    pub(crate) fn is_exhausted(&self) -> bool {
        let Self::Open { source, .. } = self else {
            return false;
        };
        let pcap::Error::PcapError(message) = &source.0 else {
            return false;
        };
        #[cfg(unix)]
        {
            [libc::EMFILE, libc::ENFILE].into_iter().any(|code| {
                let error = std::io::Error::from_raw_os_error(code).to_string();
                let words = error.split(" (os error").next().unwrap_or(&error);
                message.contains(words)
            })
        }
        #[cfg(not(unix))]
        {
            let _ = message;
            false
        }
    }

    /// What went wrong, without the link's name, for a line that names the link
    /// itself.
    ///
    /// A capture of one link that failed is that link's own refusal, so it too is
    /// given without the name. Of several, each keeps its name.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::NoInterface { refused } => match refused.as_slice() {
                [(_, only)] => only.reason(),
                several => refusals_reason(several),
            },
            Self::Open { source, .. } => source.to_string(),
            Self::Denied { source, .. } => {
                format!("this process lacks the privileges to capture on it: {source}")
            }
            Self::UnsupportedLinkType { dlt, .. } => {
                format!("it carries data-link type {dlt}, which nothing here parses")
            }
            other => other.to_string(),
        }
    }
}

/// Why no link could be captured on, from each link's refusal.
///
/// One sentence where every link was denied, which is what an unprivileged process
/// meets. Otherwise each reason once, in the order tried: a reason one link gave by
/// that link's name, and one several gave with how many. The reasons can differ, and
/// a reason repeated per link would be one fact told dozens of times: a process out of
/// descriptors meets the same refusal on every link.
fn refusals_reason(refused: &[(String, CaptureError)]) -> String {
    if refused.is_empty() {
        return "there was no link to capture on".to_owned();
    }
    if refused.iter().all(|(_, error)| error.is_denied()) {
        return "this process may not capture (opening a capture needs root)".to_owned();
    }

    let mut reasons: Vec<(String, &str, usize)> = Vec::new();
    for (link, error) in refused {
        let reason = error.reason();
        match reasons.iter_mut().find(|(told, _, _)| *told == reason) {
            Some((_, _, links)) => *links += 1,
            None => reasons.push((reason, link, 1)),
        }
    }
    reasons
        .iter()
        .map(|(reason, link, links)| match links {
            1 => format!("{link}: {reason}"),
            many => format!("{reason} ({many} links)"),
        })
        .collect::<Vec<_>>()
        .join("; ")
}

/// What the capture library said when it refused, in its own words.
///
/// This crate's type, so the binding to `libpcap` or Npcap, and its release, stay
/// internal: a caller reads the library's words through `Display`, and no signature
/// names the binding.
///
/// The words are quoted bare. The binding prefixes every message with `libpcap
/// error:`, which on Windows, where the library is Npcap, reads as a missing library
/// when one is installed and has said exactly what it refused.
#[derive(Debug)]
pub struct LibraryError(pcap::Error);

impl LibraryError {
    /// Wraps what the binding returned.
    pub(crate) fn new(error: pcap::Error) -> Self {
        Self(error)
    }
}

impl std::fmt::Display for LibraryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.0 {
            pcap::Error::PcapError(message) => f.write_str(message),
            other => other.fmt(f),
        }
    }
}

impl std::error::Error for LibraryError {}

/// Opens a filtered capture on each named link and starts reading, parsing every
/// admitted frame down to the Layer-4 segment a scanner reads.
///
/// Non-IP frames are dropped, since there is no segment behind an ARP frame. For
/// those, use [`frames`], this function's twin, which forwards whole frames.
///
/// # The stream is bounded
///
/// Most arrivals are bounded by what this host sent, and the task sending probes is
/// the one reading this. The rest are not, as the filters show. Only
/// [`ProbeKind::UdpResolve`](crate::transport::probe::ProbeKind) narrows to this scan
/// in both address families. A SYN sweep admits every IPv6 TCP segment because
/// `tcp[tcpflags]` will not compile over a next-header chain, and the three kinds that
/// read ICMP errors admit `icmp or icmp6` whole because an error names no ports. Each
/// is the right trade, and each leaves a rate the network sets.
///
/// So `queue_depth` bounds what may wait, as for [`frames`], and a full queue stalls
/// the reader instead of discarding: the kernel buffer takes up the slack, `libpcap`
/// counts what it drops, and the loss lands in [`CaptureCounts::dropped`], which a
/// report already carries.
pub fn segments(
    links: &[Zone],
    options: &CaptureOptions,
    queue_depth: usize,
) -> Result<(CaptureStream, CaptureGuard), CaptureError> {
    let (tx, rx) = mpsc::channel(queue_depth);

    let guard = spawn_captures(links, options, move |_zone, link, stop| {
        let tx = tx.clone();
        move |packet: &pcap::Packet<'_>| {
            let Some((parsed, source_mac)) = frame::parse_captured(link, packet.data) else {
                return ControlFlow::Continue(());
            };

            let mut segment = CapturedSegment {
                source: parsed.source,
                destination: Some(parsed.destination),
                protocol: parsed.protocol,
                bytes: parsed.payload.to_vec(),
                observation: Some(parsed.observation),
                source_mac,
                received_at: Instant::now(),
            };

            // Waits instead of dropping, for the reason `frames` gives.
            loop {
                match tx.try_send(segment) {
                    Ok(()) => return ControlFlow::Continue(()),
                    Err(mpsc::error::TrySendError::Closed(_)) => return ControlFlow::Break(()),
                    Err(mpsc::error::TrySendError::Full(returned)) => {
                        // A guard being dropped ends the wait for room, since its
                        // join would wait on this thread. See `CaptureGuard`.
                        if stop.load(Ordering::Relaxed) {
                            return ControlFlow::Break(());
                        }
                        segment = returned;
                        thread::sleep(QUEUE_FULL_PAUSE);
                    }
                }
            }
        }
    })?;

    Ok((rx, guard))
}

/// Opens a filtered capture on each named link and starts reading, forwarding every
/// admitted frame whole.
///
/// The twin of [`segments`], for answers outside a Layer-4 segment: an ARP exchange, a
/// neighbour advertisement, a switch announcing itself, the VLAN a frame was tagged
/// with, or the hardware address behind any of them. Each frame arrives with its link,
/// so a finding that only means something on one segment can say which.
///
/// `queue_depth` bounds how many frames may wait for the consumer at once. Multiplied
/// by [`CaptureOptions::with_snaplen`] it is also the memory this costs, so the caller
/// states it.
///
/// # A full queue stalls the reader
///
/// When the consumer falls behind, the reader thread waits with the frame it holds.
/// The kernel buffer takes up the slack, and when that fills, `libpcap` counts what it
/// discards, so the loss lands in [`CaptureCounts::dropped`], which a report already
/// carries. Discarding here would be a loss counted nowhere and indistinguishable from
/// a network with nothing to say.
pub fn frames(
    links: &[Zone],
    options: &CaptureOptions,
    queue_depth: usize,
) -> Result<(FrameStream, CaptureGuard), CaptureError> {
    let (tx, rx) = mpsc::channel(queue_depth);

    let guard = spawn_captures(links, options, move |zone, link, stop| {
        let tx = tx.clone();
        let zone = zone.clone();
        move |packet: &pcap::Packet<'_>| {
            let mut frame = CapturedFrame {
                zone: zone.clone(),
                link,
                bytes: packet.data.to_vec(),
                observed_at: timestamp_of(packet),
                received_at: Instant::now(),
            };

            // Waits instead of dropping, so the loss lands in the kernel's counter;
            // see this function's documentation.
            loop {
                match tx.try_send(frame) {
                    Ok(()) => return ControlFlow::Continue(()),
                    Err(mpsc::error::TrySendError::Closed(_)) => return ControlFlow::Break(()),
                    Err(mpsc::error::TrySendError::Full(returned)) => {
                        // A guard being dropped ends the wait for room, since its
                        // join would wait on this thread. See `CaptureGuard`.
                        if stop.load(Ordering::Relaxed) {
                            return ControlFlow::Break(());
                        }
                        frame = returned;
                        thread::sleep(QUEUE_FULL_PAUSE);
                    }
                }
            }
        }
    })?;

    Ok((rx, guard))
}

/// Opens a capture on every link that will have one, starts a reader thread per
/// capture, and returns the guard that keeps them alive.
///
/// `deliver_for` builds the per-link closure that handles each frame, the only
/// difference between [`segments`] and [`frames`]. Everything else (which failures are
/// survivable, how threads are named and stopped, when counters refresh) lives here so
/// the two cannot drift.
///
/// Interfaces that fail to open, or whose data-link type this crate cannot parse, are
/// skipped and reported by [`tell_unheard`]: a host has many, most irrelevant to a
/// given capture. Only *every* link failing is an error, since a capture with no link
/// can never hear anything, and so is any link refused for want of a descriptor; see
/// [`CaptureError::OutOfDescriptors`].
fn spawn_captures<D>(
    links: &[Zone],
    options: &CaptureOptions,
    mut deliver_for: impl FnMut(&Zone, LinkType, Arc<AtomicBool>) -> D,
) -> Result<CaptureGuard, CaptureError>
where
    D: FnMut(&pcap::Packet<'_>) -> ControlFlow<()> + Send + 'static,
{
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();
    let mut stats = Vec::new();

    // Named and counted in one line beside the per-interface ones, at verbosity 3. A
    // scan opens a capture on every interface that is up (twenty-six on an ordinary
    // laptop with a VPN and a hypervisor) once per transport, and that is where
    // someone asking which links were captured with which filter will look.
    let mut opened = 0usize;
    // Why the last reader thread refused to start, for the case where none did.
    let mut unstarted: Option<std::io::Error> = None;
    // The links that would not open, reported together once it is known whether any
    // did. See `tell_unheard`.
    let mut unheard: Vec<(&Zone, CaptureError)> = Vec::new();

    for zone in links {
        let name = zone.name();
        match open(name, options) {
            Ok(Opened {
                capture,
                link,
                warning,
                left_out,
            }) => {
                match warning {
                    Some(warning) => info!(
                        verbosity = 3,
                        "capturing on {name} (link type {link:?}), which libpcap \
                         opened with a warning: {warning}"
                    ),
                    None => info!(verbosity = 3, "capturing on {name} (link type {link:?})"),
                }
                if !left_out.is_empty() {
                    info!(
                        verbosity = 3,
                        "capturing on {name} without the filter clauses it cannot express: {}",
                        left_out.join(" or ")
                    );
                }
                opened += 1;

                let stop = stop.clone();
                let deliver = deliver_for(zone, link, stop.clone());
                let counters = Arc::new(CaptureStats::default());
                stats.push(counters.clone());
                let name = name.to_owned();

                match spawn_reader(&name.clone(), counters, move |counters| {
                    reader_loop(capture, &stop, &name, counters, deliver)
                }) {
                    Ok(handle) => handles.push(handle),
                    // As with an open failure: a host near its thread limit still
                    // captures on the links it managed, and only losing all of them is
                    // an error.
                    Err(e) => {
                        warn!("no reader thread for {}: {e}", zone.name());
                        stats.pop();
                        unstarted = Some(e);
                    }
                }
            }
            Err(e) => unheard.push((zone, e)),
        }
    }

    let exhausted: Vec<String> = unheard
        .iter()
        .filter(|(_, error)| error.is_exhausted())
        .map(|(zone, _)| zone.name().to_owned())
        .collect();
    if !exhausted.is_empty() {
        // Stops and joins the readers already started, closing their links.
        drop(CaptureGuard {
            stop,
            handles,
            stats,
            _held_back: None,
        });
        return Err(CaptureError::OutOfDescriptors { links: exhausted });
    }

    if !unheard.is_empty() {
        tell_unheard(&unheard, opened == 0);
    }

    if handles.is_empty() {
        return Err(match unstarted {
            Some(source) => CaptureError::NoReader { opened, source },
            None => CaptureError::NoInterface {
                refused: unheard
                    .into_iter()
                    .map(|(zone, error)| (zone.name().to_owned(), error))
                    .collect(),
            },
        });
    }

    info!(
        verbosity = 3,
        "capturing on {} with filter: {}",
        counted(opened as u128, "interface", "interfaces"),
        options.filter,
    );

    Ok(CaptureGuard::running(stop, handles, stats))
}

/// Reports which links could not be captured on, and why: once per link for the life
/// of the process, and on the default console only where the scan's answers depend on
/// it and no error will say so.
///
/// Every transport opens its own capture on every link, so a link that refuses one
/// refuses them all, several times a scan, and again in every scan a front end runs.
/// The refusal is a fact about the machine (an adapter Npcap is not bound to, such as
/// a hypervisor's or a VPN's, stays that way), so it is reported once, and again only
/// if it comes to matter more.
///
/// How much it matters is [`loudness`]'s question. The link is named as a person knows
/// it, with the system's name beside it on the quiet line, for someone matching it
/// against the capture library's device list.
fn tell_unheard(unheard: &[(&Zone, CaptureError)], every_link_failed: bool) {
    let links = crate::system::interface::interfaces_or_none();
    let mut told = TOLD
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    for (zone, error) in unheard {
        let link = links.iter().find(|link| link.zone() == **zone);
        let loudness = loudness(
            every_link_failed,
            link.is_some_and(|link| link.carries_default_route()),
        );
        if !told.first_time(zone.name(), loudness) {
            continue;
        }

        let known_as = link.map_or(zone.name(), |link| link.display_name());
        let reason = error.reason();
        match loudness {
            Loudness::Aloud => warn!("no capture on {known_as}: {reason}"),
            Loudness::Quiet if known_as == zone.name() => {
                warn!(verbosity = 1, "no capture on {known_as}: {reason}");
            }
            Loudness::Quiet => {
                warn!(
                    verbosity = 1,
                    "no capture on {known_as} ({}): {reason}",
                    zone.name()
                );
            }
        }
    }
}

/// How a link that could not be captured on is told about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Loudness {
    /// At verbosity 1, with the decisions behind a result: a link nothing in the scan
    /// was shown to need.
    Quiet,
    /// On the default console, because the scan's answers depend on it.
    Aloud,
}

/// How loudly a link that could not be captured on is reported.
///
/// Aloud when the scan's answers depend on it and nothing else will say so: a link
/// carrying the default route, through which every target beyond this machine's own
/// segments is reached and answers, while the scan goes on without it on the other
/// links. Where no link could be captured on at all, the capture fails with an error
/// naming every link and its cause, so these lines go quiet. Otherwise the link is one
/// of the adapters a host keeps beside the one it uses (a hypervisor's switch, a VPN's
/// tunnel, a bridge), reached only by a target on its own segment: quiet, where a
/// reader asking what went uncovered will find it.
fn loudness(every_link_failed: bool, carries_default_route: bool) -> Loudness {
    if carries_default_route && !every_link_failed {
        Loudness::Aloud
    } else {
        Loudness::Quiet
    }
}

/// The links this process has said it cannot capture on, and how loudly.
struct Told(std::collections::BTreeMap<String, Loudness>);

impl Told {
    const fn new() -> Self {
        Self(std::collections::BTreeMap::new())
    }

    /// Whether `link` should be reported at `loudness`: never reported, or reported
    /// more quietly than it now deserves. Records it either way.
    fn first_time(&mut self, link: &str, loudness: Loudness) -> bool {
        match self.0.get(link) {
            Some(&said) if said >= loudness => false,
            _ => {
                self.0.insert(link.to_owned(), loudness);
                true
            }
        }
    }
}

/// Every link this process has said it cannot capture on. See [`tell_unheard`].
static TOLD: std::sync::Mutex<Told> = std::sync::Mutex::new(Told::new());

/// Starts the thread that reads one capture, marking the capture stopped early if that
/// thread dies.
///
/// **A reader that panicked is a link that went deaf, and the record must say so while
/// the scan can still read it.** The thread is the only reader of its interface, so
/// every reply that would have arrived becomes silence a scanner cannot tell from a
/// host that did not answer; [`reader_loop`] sets the same flag when pcap ends the
/// link. The dying thread sets the mark as it unwinds, because every scanner reads its
/// capture counts while the guard is alive; set at join, it would come after the only
/// read.
///
/// Every reader starts here, so none runs without the mark.
fn spawn_reader(
    name: &str,
    counters: Arc<CaptureStats>,
    read: impl FnOnce(&CaptureStats) + Send + 'static,
) -> std::io::Result<JoinHandle<()>> {
    let link = name.to_owned();
    thread::Builder::new()
        .name(format!("capture-{name}"))
        .spawn(move || {
            let _mark = DeafOnUnwind {
                counters: &counters,
                link: &link,
            };
            read(&counters);
        })
}

/// Marks a capture stopped early when its reader unwinds. See [`spawn_reader`].
struct DeafOnUnwind<'a> {
    counters: &'a CaptureStats,
    link: &'a str,
}

impl Drop for DeafOnUnwind<'_> {
    fn drop(&mut self) {
        if thread::panicking() {
            self.counters.stopped_early.store(true, Ordering::Relaxed);
            error!(
                "the capture on {} failed and will hear nothing further; replies \
                 arriving on this link are lost from here on",
                self.link
            );
        }
    }
}

/// When the kernel says it saw this frame.
///
/// Wall-clock, because it answers "when was this host last heard from", which a reader
/// places against everything else in the record. A frame whose timestamp cannot be
/// represented is stamped with the epoch: the frame is still evidence.
fn timestamp_of(packet: &pcap::Packet<'_>) -> SystemTime {
    let seconds = u64::try_from(packet.header.ts.tv_sec).unwrap_or(0);
    let micros = u32::try_from(packet.header.ts.tv_usec).unwrap_or(0);
    UNIX_EPOCH + Duration::new(seconds, micros.saturating_mul(1_000))
}

/// The name of the capture device for the interface named `name`.
///
/// On Unix the two share a name. On Windows they do not: an interface is named
/// by its adapter GUID, `{…}`, and Npcap names the same adapter under its own
/// prefix, `\Device\NPF_{…}`. See [`npcap_device_name`].
fn device_name(name: &str) -> String {
    #[cfg(windows)]
    {
        npcap_device_name(name)
    }
    #[cfg(not(windows))]
    {
        name.to_owned()
    }
}

/// The name Npcap gives the adapter an interface list names `name`.
///
/// Npcap lists an adapter as `\Device\NPF_` followed by the GUID Windows names it by,
/// and its device list and open call use that full form. A name already in that form,
/// or one that is not a GUID, such as Npcap's own loopback adapter, is passed through
/// unchanged.
#[cfg_attr(not(windows), allow(dead_code))]
fn npcap_device_name(name: &str) -> String {
    if name.starts_with('{') {
        format!("\\Device\\NPF_{name}")
    } else {
        name.to_owned()
    }
}

/// A capture [`open`] brought up, with what it is and what `libpcap` said about
/// bringing it up.
struct Opened {
    capture: Capture<Active>,
    /// How its frames are framed.
    link: LinkType,
    /// The warning `libpcap` activated it under, if any. See [`libpcap`].
    warning: Option<String>,
    /// The clauses of its filter this link could not express, and so does not admit.
    /// See [`CaptureFilter`].
    left_out: Vec<String>,
}

/// Opens and activates a single filtered capture, returning it with the [`LinkType`]
/// its frames must be parsed as.
///
/// On Unix the capture is put into non-blocking mode and the reader waits on the
/// descriptor itself. `libpcap`'s read timeout cannot replace that: Linux's
/// memory-mapped `TPACKET` path uses it only as the timeout of its own internal `poll`
/// and polls again instead of returning, so a blocking read on an interface seeing no
/// matching frames never returns and the stop flag is never checked. BSD's `BPF`
/// (macOS) does return on timeout.
fn open(name: &str, options: &CaptureOptions) -> Result<Opened, CaptureError> {
    let (capture, warning) = libpcap::activate(
        name,
        &libpcap::Setup {
            snaplen: saturating_i32(options.snaplen),
            promiscuous: options.promiscuous,
            timeout_ms: READ_TIMEOUT_MS,
            immediate: true,
            // Left alone unless asked for, so an unchosen buffer size keeps the
            // platform `libpcap`'s default.
            buffer_bytes: options.buffer_bytes.map(saturating_i32),
        },
    )?;

    #[cfg(not(windows))]
    let capture = capture.setnonblock().map_err(|source| CaptureError::Open {
        interface: name.to_owned(),
        source: LibraryError::new(source),
    })?;

    let mut capture = capture;
    let link = LinkType::from_dlt(capture.get_datalink().0);
    if let LinkType::Unsupported(dlt) = link {
        return Err(CaptureError::UnsupportedLinkType {
            interface: name.to_owned(),
            dlt,
        });
    }

    let (filter, left_out) = options.filter.for_link(&capture)?;
    capture
        .filter(&filter, true)
        .map_err(|source| CaptureError::Filter {
            filter,
            source: LibraryError::new(source),
        })?;

    Ok(Opened {
        capture,
        link,
        warning,
        left_out,
    })
}

/// Narrows a byte count to the signed width `libpcap` takes, saturating.
///
/// Both settings this converts are sizes, meaningless when negative: a wrapped
/// snapshot length is a capture that keeps nothing, which would read as a quiet
/// network. [`CaptureOptions`] uses `u32`; this is where the library's `i32` is met.
fn saturating_i32(bytes: u32) -> i32 {
    i32::try_from(bytes).unwrap_or(i32::MAX)
}

/// Read loop for one capture: hands every admitted frame to `deliver` until it asks to
/// stop, the stop flag is set, or the capture fails. No frame ready is the normal idle
/// case.
///
/// `deliver` gets the whole `libpcap` packet, its bytes and the header carrying the
/// kernel's timestamp, and returns whether to carry on. Both outputs this module offers
/// are built on it, so the shutdown discipline, the poll and the counter cadence exist
/// once.
///
/// The loop also keeps `counters` current, since what this thread fails to read in time
/// is invisible everywhere else: a frame the kernel discards for lack of buffer space
/// never reaches the channel.
fn reader_loop(
    mut capture: Capture<Active>,
    stop: &AtomicBool,
    name: &str,
    counters: &CaptureStats,
    mut deliver: impl FnMut(&pcap::Packet<'_>) -> ControlFlow<()>,
) {
    #[cfg(not(windows))]
    let fd = capture.as_raw_fd();
    let mut since_refresh: u32 = 0;

    while !stop.load(Ordering::Relaxed) {
        // Whether this iteration read a frame, decided inside the match and acted on
        // after it: the packet borrows the capture, and refreshing the counters needs
        // it back.
        let mut read_frame = false;

        match capture.next_packet() {
            Ok(packet) => {
                read_frame = true;
                if deliver(&packet).is_break() {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(e) => {
                // Recorded as well as logged. This thread is the only reader of this
                // interface, so ending here makes it deaf for the rest of the scan,
                // and every reply that would have arrived is silence a scanner cannot
                // tell from a host that did not answer. `CaptureCounts` is the record
                // of that loss.
                if ends_the_link(&e) {
                    counters.stopped_early.store(true, Ordering::Relaxed);
                    error!(
                        "capture on {name} stopped and will hear nothing further \
                         ({e}); replies arriving on this link are lost from here on"
                    );
                }
                break;
            }
        }

        since_refresh += u32::from(read_frame);
        if since_refresh >= STATS_EVERY_FRAMES {
            refresh(&mut capture, counters);
            since_refresh = 0;
        }

        // Idle is the cheapest moment to refresh: nothing waits on this thread, and a
        // scan that ends quietly gets a final count.
        if !read_frame {
            refresh(&mut capture, counters);
            since_refresh = 0;
            #[cfg(not(windows))]
            wait_readable(fd, READ_TIMEOUT_MS);
        }
    }

    refresh(&mut capture, counters);
    let counts = counters.snapshot();
    if counts.dropped > 0 || counts.if_dropped > 0 {
        info!(
            verbosity = 1,
            "capture on {name} lost frames: {} dropped, {} dropped by the interface, of {} received",
            counts.dropped,
            counts.if_dropped,
            counts.received
        );
    }
}

/// Whether a capture ending on `error` leaves the link deaf, or just reached the end
/// of its input.
///
/// This is what [`CaptureCounts::stopped_early`] means, as a function so it can be
/// tested. A live capture never runs out of packets, so `NoMorePackets` is a savefile
/// ending normally; anything else is a receive path that stopped part-way through a
/// scan.
///
/// [`CaptureCounts::stopped_early`]: crate::model::capture::CaptureCounts::stopped_early
fn ends_the_link(error: &pcap::Error) -> bool {
    !matches!(
        error,
        pcap::Error::NoMorePackets | pcap::Error::TimeoutExpired
    )
}

/// Copies `libpcap`'s current counters into `counters`.
///
/// Failures are not reported. `pcap_stats` is unsupported on some capture sources,
/// which would otherwise log once per refresh for the whole scan; the counters stay
/// where they were, and a stalled count is visible next to a running scan.
fn refresh(capture: &mut Capture<Active>, counters: &CaptureStats) {
    if let Ok(stat) = capture.stats() {
        counters.store(&stat);
    }
}

/// Waits for `fd` to have a frame ready, giving up after `timeout_ms` so the caller can
/// re-check its stop flag or deadline. Poll failures are not reported: the next read
/// reports anything really wrong, and an interrupted poll costs one extra loop.
#[cfg(not(windows))]
fn wait_readable(fd: std::os::unix::io::RawFd, timeout_ms: i32) {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    // SAFETY: `poll_fd` is a single initialized `pollfd` and the count says so; `poll`
    // reads it and writes only `revents`.
    unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
}

/// A handle for putting whole frames on a link.
///
/// The send half of the library the receive half uses. Sending through another library
/// would open two on one interface for one scan, such as a `pnet` channel whose
/// receiver is discarded beside the `pcap` capture, and a discarded receiver is a
/// kernel buffer nothing drains.
///
/// A separate handle from the reading one, because a capture cannot be read and
/// written through the same borrow while a reader thread is parked in `next_packet`.
pub struct FrameSender {
    capture: Capture<Active>,
}

impl FrameSender {
    /// Opens a send-only handle on `link`.
    ///
    /// The filter cannot match: a capture with no filter would fill a kernel buffer
    /// nobody reads. `less 0` asks for frames shorter than nothing.
    pub fn open(link: &str) -> Result<Self, CaptureError> {
        let (mut capture, _) = libpcap::activate(
            link,
            &libpcap::Setup {
                snaplen: 1,
                promiscuous: false,
                timeout_ms: 1,
                immediate: false,
                buffer_bytes: None,
            },
        )?;

        capture
            .filter("less 0", true)
            .map_err(|source| CaptureError::Open {
                interface: link.to_owned(),
                source: LibraryError::new(source),
            })?;

        Ok(Self { capture })
    }
}

impl FrameSink for FrameSender {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.capture.sendpacket(frame).map_err(|e| e.to_string())
    }
}

/// Somewhere to put a frame.
///
/// A trait because it is the seam a test drives a scanner through, as [`FrameStream`]
/// is on the receive side. A fake segment implements this, observes what a scanner
/// emits, and answers on the stream, with no interface and no privileges.
pub trait FrameSink: Send {
    /// Puts `frame` on the wire whole, link header included.
    ///
    /// The error is a string because a caller can only report it. What matters at the
    /// call site is that a failure means the frame did not leave.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String>;
}

/// One link, opened for both directions and driven by a single thread.
///
/// The shape a request-and-wait exchange wants: put a frame on the wire, then read
/// until the answer arrives or the deadline passes. Both halves borrow the same handle
/// mutably, so this is one type, and not what [`frames`] gives a scanner, whose reader
/// lives on its own thread.
///
/// The filter is the caller's, since the reader decides what a frame is worth.
pub struct FrameChannel {
    capture: Capture<Active>,
    /// How long [`next_frame`](Self::next_frame) waits for a frame. Windows has no
    /// descriptor to wait on, and its capture's own read timeout does the waiting.
    #[cfg(not(windows))]
    wait_ms: i32,
    /// The frame [`next_frame`](Self::next_frame) last read, copied out of `libpcap`'s
    /// buffer so reading it and waiting for it can be separate steps.
    frame: Vec<u8>,
}

impl FrameChannel {
    /// Opens `link` for sending and receiving, admitting what `filter` admits.
    ///
    /// `read_timeout` bounds how long [`next_frame`](Self::next_frame) waits, so a
    /// caller with a deadline can honour it.
    pub fn open(
        link: &str,
        filter: &str,
        read_timeout: std::time::Duration,
    ) -> Result<Self, CaptureError> {
        let wait_ms = i32::try_from(read_timeout.as_millis()).unwrap_or(i32::MAX);
        let (capture, _) = libpcap::activate(
            link,
            &libpcap::Setup {
                snaplen: saturating_i32(REPLY_SNAP_LEN),
                promiscuous: false,
                timeout_ms: wait_ms,
                immediate: true,
                buffer_bytes: None,
            },
        )?;

        // Non-blocking, with the wait done on the descriptor, as in `open`: on Linux a
        // blocking read waits for a frame whatever the read timeout says. See
        // `next_frame`.
        #[cfg(not(windows))]
        let capture = capture.setnonblock().map_err(|source| CaptureError::Open {
            interface: link.to_owned(),
            source: LibraryError::new(source),
        })?;

        let mut capture = capture;
        capture
            .filter(filter, true)
            .map_err(|source| CaptureError::Filter {
                filter: filter.to_owned(),
                source: LibraryError::new(source),
            })?;

        Ok(Self {
            capture,
            #[cfg(not(windows))]
            wait_ms,
            frame: Vec::new(),
        })
    }

    /// The next frame the filter admitted, or `None` if none arrived within the read
    /// timeout. A caller with deadline left should ask again.
    ///
    /// # How the wait is bounded
    ///
    /// On Unix the read never blocks. A frame already waiting is returned at once;
    /// otherwise the wait is a `poll` on the capture's descriptor, bounded by the read
    /// timeout, followed by one more read. Every reader thread here does the same,
    /// because `libpcap`'s read timeout does not bound a blocking read on Linux: an
    /// address resolution waiting on a neighbour that will never answer would wait for
    /// an unrelated frame to pass the filter, which on a quiet link is never.
    ///
    /// The read comes before the wait because `libpcap` may already hold frames it read
    /// from the kernel in one batch, which the descriptor would not announce. Windows
    /// keeps the blocking read, whose timeout Npcap honours.
    pub fn next_frame(&mut self) -> Option<&[u8]> {
        if self.read_one() {
            return Some(&self.frame);
        }

        #[cfg(not(windows))]
        {
            wait_readable(self.capture.as_raw_fd(), self.wait_ms);
            if self.read_one() {
                return Some(&self.frame);
            }
        }

        None
    }

    /// Reads one frame into `frame`, if one is ready, and says whether one was.
    fn read_one(&mut self) -> bool {
        match self.capture.next_packet() {
            Ok(packet) => {
                self.frame.clear();
                self.frame.extend_from_slice(packet.data);
                true
            }
            Err(_) => false,
        }
    }
}

impl FrameSink for FrameChannel {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.capture.sendpacket(frame).map_err(|e| e.to_string())
    }
}

/// Brings a capture handle up: the one step taken through `libpcap` directly instead
/// of the `pcap` crate.
///
/// # Why this step
///
/// `pcap_activate` has three kinds of answer. Zero is success and a negative status is
/// failure. A positive status is a *warning*: the handle is live and capturing, but not
/// quite what was asked for. `PCAP_WARNING_PROMISC_NOTSUP` is a link that will not go
/// promiscuous. `PCAP_WARNING` is, among other things, how Linux brings up a link whose
/// hardware type `libpcap` cannot map (a GRE tunnel, an `ip6tnl` or `ip6gre` link),
/// which it serves cooked as `DLT_LINUX_SLL` and [`LinkType::LinuxSll`] reads.
///
/// The `pcap` crate's `Capture::open` treats every non-zero status as failure and
/// closes the handle, warnings included. Through it, a GRE tunnel, or any link that
/// declined to be promiscuous, could not be captured on, and a scan through one would
/// read its targets as down.
///
/// The crate offers no way round that: a handle becomes active only through that call,
/// and cannot move from the crate's inactive type to its active one without closing
/// it or leaking its wrapper. So the handle is created and activated here and adopted
/// into a `Capture<Active>` immediately, through the crate's conversion for a raw
/// handle. From then on every read, filter, statistic, send and the close go through
/// the crate's API.
///
/// Forking the crate would mean carrying a fork for one comparison, and capturing on
/// Linux's `any` device would serve only Linux and copy every link's traffic into the
/// filter. The seam here is eight functions `libpcap` has exported unchanged since 1.5,
/// all of which the crate also declares, so linking asks nothing new of `libpcap` or
/// Npcap.
mod libpcap {
    use std::ffi::{CStr, CString, c_char, c_int};
    use std::marker::{PhantomData, PhantomPinned};
    use std::ptr::NonNull;

    use pcap::{Active, Capture};

    use super::{CaptureError, LibraryError, device_name};

    /// `libpcap`'s capture handle, which this side only holds a pointer to.
    ///
    /// Declared here because the `pcap` crate keeps its bindings private. The pointer
    /// is converted to the crate's type once, in [`activate`]; both name the same C
    /// struct.
    #[repr(C)]
    struct Handle {
        _opaque: [u8; 0],
        _unmovable: PhantomData<(*mut u8, PhantomPinned)>,
    }

    /// The size `libpcap` requires of the buffer `pcap_create` writes an error into,
    /// `PCAP_ERRBUF_SIZE`.
    const ERRBUF_SIZE: usize = 256;

    // `pcap_activate`'s statuses, from `pcap/pcap.h`. Negative statuses are failures
    // and positive ones warnings; these are the ones this module names itself where
    // `libpcap` left its error buffer empty.
    const PCAP_WARNING: c_int = 1;
    const PCAP_WARNING_PROMISC_NOTSUP: c_int = 2;
    const PCAP_WARNING_TSTAMP_TYPE_NOTSUP: c_int = 3;
    pub(super) const PCAP_ERROR_NO_SUCH_DEVICE: c_int = -5;
    pub(super) const PCAP_ERROR_PERM_DENIED: c_int = -8;
    const PCAP_ERROR_IFACE_NOT_UP: c_int = -9;
    pub(super) const PCAP_ERROR_PROMISC_PERM_DENIED: c_int = -11;

    unsafe extern "C" {
        fn pcap_create(source: *const c_char, errbuf: *mut c_char) -> *mut Handle;
        fn pcap_set_snaplen(handle: *mut Handle, snaplen: c_int) -> c_int;
        fn pcap_set_promisc(handle: *mut Handle, promisc: c_int) -> c_int;
        fn pcap_set_timeout(handle: *mut Handle, to_ms: c_int) -> c_int;
        fn pcap_set_immediate_mode(handle: *mut Handle, immediate: c_int) -> c_int;
        fn pcap_set_buffer_size(handle: *mut Handle, buffer_size: c_int) -> c_int;
        fn pcap_activate(handle: *mut Handle) -> c_int;
        fn pcap_geterr(handle: *mut Handle) -> *mut c_char;
    }

    /// What a handle is set to before it is activated.
    ///
    /// Grouped because `libpcap` accepts each only on a handle not yet activated, and
    /// the crate's builders for them are on the type this module does not use.
    pub(super) struct Setup {
        pub(super) snaplen: c_int,
        pub(super) promiscuous: bool,
        pub(super) timeout_ms: c_int,
        pub(super) immediate: bool,
        /// `None` leaves `libpcap`'s own default in place.
        pub(super) buffer_bytes: Option<c_int>,
    }

    /// Creates a capture handle on `link`, sets it up, and activates it, returning it
    /// with the warning it was activated under, if any.
    ///
    /// A warning is not a failure: the handle is live, and the warning says how it
    /// differs from what was asked for. The caller decides whether to report it.
    pub(super) fn activate(
        link: &str,
        setup: &Setup,
    ) -> Result<(Capture<Active>, Option<String>), CaptureError> {
        let device = CString::new(device_name(link)).map_err(|_| CaptureError::Open {
            interface: link.to_owned(),
            source: LibraryError::new(pcap::Error::InvalidInputString),
        })?;

        let mut errbuf = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: `device` is a NUL-terminated string that outlives the call,
        // and `errbuf` is the `PCAP_ERRBUF_SIZE` bytes `pcap_create` may write.
        let created = unsafe { pcap_create(device.as_ptr(), errbuf.as_mut_ptr()) };
        let Some(created) = NonNull::new(created) else {
            // SAFETY: on failure `pcap_create` has written a NUL-terminated message
            // into `errbuf`, which was zeroed, so it is terminated either way.
            let message = unsafe { CStr::from_ptr(errbuf.as_ptr()) };
            return Err(CaptureError::Open {
                interface: link.to_owned(),
                source: LibraryError::new(pcap::Error::PcapError(
                    message.to_string_lossy().into_owned(),
                )),
            });
        };

        // Adopted before activation, so every path out of this function, the failures
        // below included, closes it through the crate's `Drop`, as `libpcap` asks for a
        // handle whose activation failed. Only the pointer is read from it until
        // activation succeeds.
        let capture: Capture<Active> = Capture::from(created.cast());
        let handle = capture.as_ptr().cast::<Handle>();

        // SAFETY: `handle` is the live handle `pcap_create` returned, owned by
        // `capture` for the rest of this function, and not yet activated, the only
        // state in which these calls are defined. Each errors only on an activated
        // handle.
        unsafe {
            pcap_set_snaplen(handle, setup.snaplen);
            pcap_set_promisc(handle, c_int::from(setup.promiscuous));
            pcap_set_timeout(handle, setup.timeout_ms);
            pcap_set_immediate_mode(handle, c_int::from(setup.immediate));
            if let Some(bytes) = setup.buffer_bytes {
                pcap_set_buffer_size(handle, bytes);
            }
        }

        // SAFETY: as above; these settings were made for this activation.
        let status = unsafe { pcap_activate(handle) };
        let message = || status_message(handle, status);

        match status {
            0 => Ok((capture, None)),
            warning if warning > 0 => Ok((capture, Some(message()))),
            failure => Err(refusal(link, failure, message())),
        }
    }

    /// The error reported for a handle that failed to activate with `status`.
    ///
    /// Privilege is read from the status alone. `libpcap` reports a missing privilege
    /// as its own status on every platform, while its wording differs between
    /// platforms and releases, so matching the words would misattribute failures.
    pub(super) fn refusal(link: &str, status: c_int, message: String) -> CaptureError {
        let source = LibraryError::new(pcap::Error::PcapError(message));
        match status {
            PCAP_ERROR_PERM_DENIED | PCAP_ERROR_PROMISC_PERM_DENIED => CaptureError::Denied {
                interface: link.to_owned(),
                source,
            },
            _ => CaptureError::Open {
                interface: link.to_owned(),
                source,
            },
        }
    }

    /// What `libpcap` said about `status`, in its own words where it wrote some.
    ///
    /// `pcap_geterr` holds the detail for most statuses and is empty for a few, where
    /// the status is all that is known. Those are named here as `pcap_statustostr`
    /// would, since that function is not declared by the crate.
    fn status_message(handle: *mut Handle, status: c_int) -> String {
        // SAFETY: `handle` is live, and `pcap_geterr` returns a NUL-terminated pointer
        // into it, valid until the next call on the handle. It is copied out first.
        let said = unsafe { CStr::from_ptr(pcap_geterr(handle)) }
            .to_string_lossy()
            .into_owned();
        if !said.is_empty() {
            return said;
        }

        match status {
            PCAP_WARNING => "a generic warning".to_owned(),
            PCAP_WARNING_PROMISC_NOTSUP => {
                "this device does not support promiscuous mode".to_owned()
            }
            PCAP_WARNING_TSTAMP_TYPE_NOTSUP => {
                "this device does not support the requested timestamp type".to_owned()
            }
            PCAP_ERROR_NO_SUCH_DEVICE => "no such device exists".to_owned(),
            PCAP_ERROR_PERM_DENIED => "permission denied".to_owned(),
            PCAP_ERROR_IFACE_NOT_UP => "the interface is not up".to_owned(),
            PCAP_ERROR_PROMISC_PERM_DENIED => {
                "permission denied to put it in promiscuous mode".to_owned()
            }
            other => format!("activation failed with status {other}"),
        }
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

    /// An adapter that refuses is named once, and the capture library's own words say
    /// why. The `pcap` crate prefixes every message with `libpcap error:`, which on
    /// Windows reads as a missing library when Npcap is installed and has said exactly
    /// what is wrong.
    #[test]
    fn a_refused_open_names_the_adapter_once_and_quotes_the_library() {
        let guid = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
        let message = "Error opening adapter: Network interface was not found.";
        let refused = CaptureError::Open {
            interface: guid.to_owned(),
            source: LibraryError::new(pcap::Error::PcapError(message.to_owned())),
        };

        assert_eq!(
            refused.to_string(),
            format!("{guid} could not be opened: {message}")
        );
        assert_eq!(refused.reason(), message, "the reason leaves the name out");
    }

    /// A link refused for want of privilege is reported as such, and one refused for
    /// anything else is not.
    ///
    /// The status decides it: `libpcap` reports a missing privilege as its own status,
    /// and blaming privilege for a failure it did not cause misleads someone who
    /// already has it.
    #[test]
    fn only_a_refusal_libpcap_reports_as_denied_is_blamed_on_privilege() {
        for status in [
            libpcap::PCAP_ERROR_PERM_DENIED,
            libpcap::PCAP_ERROR_PROMISC_PERM_DENIED,
        ] {
            let refused =
                libpcap::refusal("eth0", status, "socket: Operation not permitted".into());
            assert!(refused.is_denied(), "status {status}");
            assert!(refused.to_string().contains("privileges"), "{refused}");
        }

        for status in [libpcap::PCAP_ERROR_NO_SUCH_DEVICE, -1] {
            let refused = libpcap::refusal("eth0", status, "no such device".into());
            assert!(!refused.is_denied(), "status {status}");
            assert!(!refused.to_string().contains("privilege"), "{refused}");
        }
    }

    /// A link refused because the process had no descriptor left is told apart from
    /// one that declined, so the capture can refuse whole instead of listening on the
    /// links it reached and reading the rest's replies as silence. `libpcap` gives the
    /// shortage the status of any failure to open, and says which it was only in the C
    /// library's words for the errno.
    #[cfg(unix)]
    #[test]
    fn a_link_refused_for_want_of_a_descriptor_is_told_apart_from_one_that_declined() {
        let words = |code| {
            let error = std::io::Error::from_raw_os_error(code).to_string();
            error.split(" (os error").next().unwrap().to_owned()
        };
        for code in [libc::EMFILE, libc::ENFILE] {
            let refused = libpcap::refusal(
                "utun4",
                -1,
                format!("(cannot open BPF device) /dev/bpf0: {}", words(code)),
            );
            assert!(refused.is_exhausted(), "{refused}");
            assert!(!refused.is_denied());
        }

        let declined = libpcap::refusal("utun4", -1, "no such device".into());
        assert!(!declined.is_exhausted());
        let denied = libpcap::refusal(
            "utun4",
            libpcap::PCAP_ERROR_PERM_DENIED,
            words(libc::EACCES),
        );
        assert!(!denied.is_exhausted());

        let out = CaptureError::OutOfDescriptors {
            links: vec!["utun4".into(), "utun5".into()],
        };
        assert_eq!(
            out.to_string(),
            "no capture on 2 links (file limit reached)"
        );
    }

    /// A capture no link would take names each link and its reason, and blames
    /// privilege in one sentence only where privilege refused them all.
    #[test]
    fn a_capture_no_link_would_take_says_why_each_refused() {
        let denied = |link: &str| CaptureError::Denied {
            interface: link.to_owned(),
            source: LibraryError::new(pcap::Error::PcapError("Operation not permitted".into())),
        };
        let filter = CaptureError::Filter {
            filter: "ether dst 02:00:00:00:00:01".into(),
            source: LibraryError::new(pcap::Error::PcapError(
                "ethernet addresses supported only on ethernet/FDDI/token ring".into(),
            )),
        };

        let unprivileged = CaptureError::NoInterface {
            refused: vec![
                ("eth0".into(), denied("eth0")),
                ("wg0".into(), denied("wg0")),
            ],
        };
        assert!(unprivileged.is_denied());
        assert_eq!(
            unprivileged.to_string(),
            "no link could be captured on, so nothing could be heard: this process may \
             not capture (opening a capture needs root)"
        );

        let root = CaptureError::NoInterface {
            refused: vec![("wg0".into(), filter)],
        };
        assert!(!root.is_denied());
        let said = root.to_string();
        assert!(said.contains("wg0: the filter"), "{said}");
        assert!(said.contains("ethernet addresses"), "{said}");
        assert!(
            !said.contains("root") && !said.contains("privilege"),
            "{said}"
        );

        let mixed = CaptureError::NoInterface {
            refused: vec![
                ("eth0".into(), denied("eth0")),
                (
                    "gre1".into(),
                    CaptureError::UnsupportedLinkType {
                        interface: "gre1".into(),
                        dlt: 778,
                    },
                ),
            ],
        };
        assert!(
            !mixed.is_denied(),
            "privilege would not have made gre1 parseable"
        );
        let said = mixed.to_string();
        assert!(
            said.contains("eth0: this process lacks the privileges"),
            "{said}"
        );
        assert!(
            said.contains("gre1: it carries data-link type 778"),
            "{said}"
        );
    }

    /// Links refused for one reason are told it once, with how many there were, and a
    /// link refused for its own reason keeps its name.
    ///
    /// A process out of descriptors is refused on every link in the same words; told
    /// per link, one fact would run to two thousand characters on a machine with a few
    /// dozen interfaces.
    #[test]
    fn links_refused_for_one_reason_are_told_it_once() {
        let exhausted = |link: &str| {
            (
                link.to_owned(),
                CaptureError::Open {
                    interface: link.to_owned(),
                    source: LibraryError::new(pcap::Error::PcapError(
                        "/dev/bpf: Too many open files".into(),
                    )),
                },
            )
        };
        let links = ["en0", "en1", "utun0", "bridge0"];

        let alike = CaptureError::NoInterface {
            refused: links.iter().map(|link| exhausted(link)).collect(),
        };
        assert_eq!(
            alike.to_string(),
            "no link could be captured on, so nothing could be heard: \
             /dev/bpf: Too many open files (4 links)"
        );

        let mut refused: Vec<_> = links.iter().map(|link| exhausted(link)).collect();
        refused.insert(
            1,
            (
                "gre1".into(),
                CaptureError::UnsupportedLinkType {
                    interface: "gre1".into(),
                    dlt: 778,
                },
            ),
        );
        assert_eq!(
            CaptureError::NoInterface { refused }.reason(),
            "/dev/bpf: Too many open files (4 links); \
             gre1: it carries data-link type 778, which nothing here parses"
        );
    }

    /// Through the real opening path: a link that does not exist is refused, and the
    /// error blames privilege exactly when the refusal was one.
    ///
    /// Which refusal a machine gives varies. An unprivileged Linux process is denied
    /// before the device is looked up, and a macOS user in `access_bpf` or a root
    /// process is told there is no such device. The property holds in both, and the
    /// link is named wherever privilege is not the whole answer.
    #[test]
    fn a_capture_that_could_not_open_blames_privilege_only_when_it_was_denied() {
        let link = Zone::unresolved("zondnone0");
        let refused = frames(
            std::slice::from_ref(&link),
            &CaptureOptions::for_replies("tcp"),
            1,
        )
        .err()
        .expect("no such link can be captured on");
        let said = refused.to_string();

        assert_eq!(said.contains("needs root"), refused.is_denied(), "{said}");
        if !refused.is_denied() {
            assert!(said.contains("zondnone0"), "{said}");
            assert!(!said.contains("privilege"), "{said}");
        }
    }

    /// A dead capture of `dlt`, which compiles filters for that link type with
    /// no device behind it.
    fn link_of(dlt: i32) -> Capture<pcap::Dead> {
        Capture::dead(pcap::Linktype(dlt)).expect("a dead capture")
    }

    /// `DLT_RAW`, how a WireGuard or IP-in-IP tunnel comes up on Linux.
    const RAW: i32 = 12;

    /// Of a set of alternatives, a link keeps the ones it can express, leaves out the
    /// rest, and says which it left out.
    #[test]
    fn alternatives_are_narrowed_to_what_a_link_can_express() {
        let filter = CaptureFilter::any_of(["(ether dst 01:00:0c:cc:cc:cc)", "(tcp)"]);

        let (expression, left_out) = filter.for_link(&link_of(RAW)).expect("tcp compiles");
        assert_eq!(expression, "(tcp)");
        assert_eq!(left_out, ["(ether dst 01:00:0c:cc:cc:cc)"]);

        let (expression, left_out) = filter
            .for_link(&link_of(1))
            .expect("Ethernet expresses both");
        assert_eq!(expression, "(ether dst 01:00:0c:cc:cc:cc) or (tcp)");
        assert!(left_out.is_empty());
    }

    /// A clause nothing can express is a mistake, and is refused.
    ///
    /// Leaving a clause out is sound only because the link could not carry what it
    /// matches. A typo matches nothing anywhere, and dropping it silently would hide
    /// traffic on every link with nothing said.
    #[test]
    fn a_clause_no_link_can_express_is_refused_rather_than_left_out() {
        let filter = CaptureFilter::any_of(["(tcp)", "(ether dts 01:00:0c:cc:cc:cc)"]);

        for dlt in [RAW, 1] {
            match filter.for_link(&link_of(dlt)) {
                Err(CaptureError::Filter { filter, .. }) => {
                    assert_eq!(filter, "(ether dts 01:00:0c:cc:cc:cc)");
                }
                other => panic!("a malformed clause was accepted on {dlt}: {other:?}"),
            }
        }
    }

    /// A link that can express none of the alternatives is refused, naming the whole
    /// filter.
    #[test]
    fn a_link_that_can_express_no_alternative_is_refused() {
        let filter =
            CaptureFilter::any_of(["(ether dst 01:00:0c:cc:cc:cc)", "(ether proto 0x88cc)"]);

        match filter.for_link(&link_of(RAW)) {
            Err(CaptureError::Filter { filter: named, .. }) => {
                assert_eq!(named, filter.to_string());
            }
            other => panic!("a filter admitting nothing was accepted: {other:?}"),
        }
    }

    /// An expression is compiled whole. A scan's reply filter is one, since every part
    /// is needed to hear the answers, and a link that can express only some of it is
    /// refused.
    #[test]
    fn an_expression_is_never_narrowed() {
        let written = "tcp and ether src 02:00:00:00:00:01";
        let (expression, left_out) = CaptureFilter::from(written)
            .for_link(&link_of(RAW))
            .expect("an expression is handed on as written");

        assert_eq!(expression, written);
        assert!(left_out.is_empty());
        assert!(
            link_of(RAW).compile(&expression, true).is_err(),
            "and the link then refuses it whole"
        );
    }

    /// A frame channel bounds its own wait on the descriptor, since `libpcap`'s read
    /// timeout does not end a blocking read.
    ///
    /// On Linux the memory-mapped path polls again, and the read returns only when a
    /// frame passes the filter, so an address resolution waiting on a neighbour that
    /// will never answer waits as long as the link stays quiet. This holds that the
    /// capture is non-blocking; that the wait then ends on a quiet Linux link is Tier
    /// 3's to show.
    ///
    /// Needs the right to capture on loopback, and passes silently without it.
    #[test]
    fn a_frame_channel_bounds_its_wait_itself_rather_than_trusting_libpcap() {
        let Some(loopback) = crate::system::interface::interfaces()
            .expect("this machine's interfaces")
            .into_iter()
            .find(|link| link.is_loopback())
        else {
            return;
        };

        let timeout = Duration::from_millis(50);
        let mut channel = match FrameChannel::open(loopback.name(), "less 0", timeout) {
            Ok(channel) => channel,
            Err(refused) if refused.is_denied() => return,
            Err(refused) => panic!("the loopback would not open: {refused}"),
        };

        #[cfg(not(windows))]
        assert!(
            channel.capture.is_nonblock(),
            "a blocking read is bounded by nothing on Linux"
        );

        let started = Instant::now();
        assert_eq!(channel.next_frame(), None, "`less 0` admits nothing");
        let waited = started.elapsed();
        assert!(
            waited >= timeout / 2 && waited < Duration::from_secs(1),
            "a {timeout:?} wait took {waited:?}"
        );
    }

    /// A link the scan's answers depend on is reported on the default console, and one
    /// they do not where a reader asking what went uncovered looks. A host keeps
    /// hypervisor, VPN and bridge adapters beside the one it uses, and reporting each on
    /// every scan would be noise.
    ///
    /// Where no link was heard at all the capture's error names every link and its
    /// cause, so the lines here would only repeat it.
    #[test]
    fn a_failed_link_is_told_aloud_only_when_answers_depend_on_it() {
        assert_eq!(loudness(false, false), Loudness::Quiet, "a spare adapter");
        assert_eq!(
            loudness(false, true),
            Loudness::Aloud,
            "the link off-segment targets answer through"
        );
        assert_eq!(
            loudness(true, false),
            Loudness::Quiet,
            "no link heard at all, which the error says"
        );
        assert_eq!(
            loudness(true, true),
            Loudness::Quiet,
            "nor the default route's, when the error names it too"
        );
    }

    /// Every transport a scan opens asks every link again, so a link that refused is
    /// reported once, and again only if it comes to matter more.
    #[test]
    fn a_failed_link_is_told_about_once_unless_it_comes_to_matter_more() {
        let mut told = Told::new();
        let guid = "{4D36E972-E325-11CE-BFC1-08002BE10318}";

        assert!(told.first_time(guid, Loudness::Quiet));
        assert!(
            !told.first_time(guid, Loudness::Quiet),
            "a second transport"
        );
        assert!(told.first_time(guid, Loudness::Aloud), "now it matters");
        assert!(!told.first_time(guid, Loudness::Aloud));
        assert!(
            !told.first_time(guid, Loudness::Quiet),
            "said louder already"
        );
        assert!(told.first_time("eth1", Loudness::Quiet), "another link");
    }

    /// Npcap opens an adapter by its own name, the Windows GUID under the driver's
    /// prefix. Given the bare GUID from an interface list, the capture every raw
    /// strategy relies on would fail to open.
    #[test]
    fn an_adapter_guid_is_named_the_way_npcap_names_it() {
        let guid = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
        assert_eq!(npcap_device_name(guid), format!("\\Device\\NPF_{guid}"));
        assert_eq!(
            npcap_device_name(&format!("\\Device\\NPF_{guid}")),
            format!("\\Device\\NPF_{guid}"),
            "a name already in Npcap's form is left alone"
        );
        assert_eq!(npcap_device_name("en0"), "en0");
    }

    /// The stamp is taken where the segment is taken, so a round trip measured against
    /// it carries the path and not the queue.
    #[test]
    fn a_segment_is_stamped_before_it_is_queued() {
        use std::net::Ipv4Addr;

        use pnet_packet::ip::IpNextHeaderProtocols;

        let before = Instant::now();
        let segment = CapturedSegment::synthetic(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpNextHeaderProtocols::Tcp.0,
            vec![0; 20],
        );
        let after = Instant::now();

        assert!(segment.received_at >= before && segment.received_at <= after);
    }
    use super::*;

    /// A snapshot length below what the deepest header stack needs is raised to it.
    ///
    /// The field bounds what this process can see of a payload, enforced by the
    /// kernel. `libpcap`'s manual leaves a zero undefined, so it must never be passed.
    #[test]
    fn a_snapshot_length_too_short_to_read_a_reply_is_raised_to_one_that_can() {
        for asked in [0, 1, MIN_SNAP_LEN - 1] {
            let options = CaptureOptions::for_replies("tcp").with_snaplen(asked);
            assert_eq!(
                options.snaplen, MIN_SNAP_LEN,
                "a snapshot length of {asked} reached libpcap"
            );
        }

        // A length the caller meant is kept, on either side of the floor.
        for asked in [MIN_SNAP_LEN, MIN_SNAP_LEN + 1, REPLY_SNAP_LEN] {
            assert_eq!(
                CaptureOptions::for_replies("tcp")
                    .with_snaplen(asked)
                    .snaplen,
                asked
            );
        }
    }

    /// A scan's captures keep everything a reply is read for, and no more than a
    /// standard Ethernet frame, at the platform's own buffer.
    ///
    /// The upper bound is what a generous setting breaks. Linux sizes its capture
    /// ring's slots from the snapshot length, so whole 64 KB frames fit 32 at the
    /// default buffer, and a scan's own bursts overflow it: answers dropped, ports
    /// asked again, the scan twice as slow on a path that lost nothing. The lower bound
    /// is the longest reply read whole, an ICMPv6 error, behind a doubly tagged
    /// Ethernet header. The buffer is left to the platform because a capture is opened
    /// on every link that is up and its buffer is paid on each.
    ///
    /// This pins the settings. That they hold a scan's bursts is measured on the wire,
    /// by a full-range scan's `dropped` count.
    #[test]
    fn a_scans_captures_keep_a_whole_standard_frame_and_no_more() {
        const STANDARD_ETHERNET_FRAME: u32 = 14 + 2 * 4 + 1_500;
        const LONGEST_ICMPV6_ERROR: u32 = 1_280;

        for (opened, options) in [
            ("replies", CaptureOptions::for_replies("tcp")),
            ("link traffic", CaptureOptions::for_link_traffic("arp")),
        ] {
            assert!(
                options.snaplen <= STANDARD_ETHERNET_FRAME,
                "a capture of {opened} keeps {} bytes of a frame",
                options.snaplen
            );
            assert!(
                options.snaplen >= 14 + 2 * 4 + LONGEST_ICMPV6_ERROR,
                "a capture of {opened} cuts the longest reply it reads whole"
            );
            assert_eq!(
                options.buffer_bytes, None,
                "a capture of {opened} sets a buffer paid on every link"
            );
        }
    }

    /// A guard over fabricated counters, standing in for one whose capture threads
    /// would need an interface and root.
    fn guard_over(stats: Vec<Arc<CaptureStats>>) -> CaptureGuard {
        CaptureGuard {
            stop: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
            stats,
            _held_back: None,
        }
    }

    fn stats_of(received: u32, dropped: u32, if_dropped: u32) -> Arc<CaptureStats> {
        let stats = Arc::new(CaptureStats::default());
        stats.store(&pcap::Stat {
            received,
            dropped,
            if_dropped,
        });
        stats
    }

    /// A transport captures on every interface that is up, so the drop count a scanner
    /// acts on must cover the whole receive path: a reply lost on the interface the
    /// probe went out of is lost whatever the others managed.
    #[test]
    fn counts_are_summed_across_every_live_capture() {
        let guard = guard_over(vec![stats_of(100, 3, 1), stats_of(40, 0, 0)]);

        assert_eq!(
            guard.counts(),
            Some(CaptureCounts {
                received: 140,
                dropped: 3,
                if_dropped: 1,
                stopped_early: 0,
            })
        );
    }

    /// Which endings leave a link deaf, and which are a capture finishing.
    ///
    /// The flag is set inside a loop that needs a live capture, so the decision is a
    /// function and this tests it. Counting every `Err` would report a savefile read to
    /// its end as a lost interface; counting none would hide every lost interface.
    #[test]
    fn a_capture_that_ran_out_of_packets_did_not_lose_its_link() {
        assert!(!ends_the_link(&pcap::Error::NoMorePackets));
        assert!(!ends_the_link(&pcap::Error::TimeoutExpired));

        for failure in [
            pcap::Error::PcapError("the device went away".to_string()),
            pcap::Error::InvalidString,
            pcap::Error::IoError(std::io::ErrorKind::PermissionDenied),
        ] {
            assert!(
                ends_the_link(&failure),
                "{failure:?} left the link readable"
            );
        }
    }

    /// A capture that stopped is counted, in captures rather than frames, so a scan
    /// across several interfaces says how many went deaf.
    ///
    /// The counters are what a report carries, and a capture that ended is the most
    /// complete form of the loss they make visible: an interface that hears nothing
    /// more, whose silence a scanner cannot tell from hosts that did not answer. Logged
    /// but not counted, a run could report a healthy receive path with one of eight
    /// links dead since the first second.
    #[test]
    fn a_capture_that_stopped_early_is_counted_as_one() {
        let lasted = stats_of(100, 0, 0);
        let stopped = stats_of(4, 0, 0);
        stopped.stopped_early.store(true, Ordering::Relaxed);

        assert_eq!(lasted.snapshot().stopped_early, 0);
        assert_eq!(stopped.snapshot().stopped_early, 1);

        // Summed across the guard's captures, so the number is how many links were
        // lost.
        let guard = guard_over(vec![lasted, stopped, stats_of(7, 0, 0)]);
        let counts = guard.counts().expect("three captures");
        assert_eq!(counts.stopped_early, 1);
        assert_eq!(counts.received, 111, "the frames they did hear still count");

        let all_stopped: Vec<_> = (0..3)
            .map(|_| {
                let stats = stats_of(1, 0, 0);
                stats.stopped_early.store(true, Ordering::Relaxed);
                stats
            })
            .collect();
        assert_eq!(
            guard_over(all_stopped)
                .counts()
                .expect("three captures")
                .stopped_early,
            3
        );
    }

    /// The distinction the `Option` exists for: no capture is not a capture that lost
    /// nothing.
    #[test]
    fn a_guard_over_no_capture_reports_nothing_rather_than_zero() {
        assert_eq!(CaptureGuard::noop().counts(), None);
        assert_eq!(guard_over(Vec::new()).counts(), None);
    }

    /// `pcap_stats` is cumulative from the start of the capture, so a refresh replaces
    /// the previous reading. Accumulating would count every dropped frame once per
    /// refresh.
    #[test]
    fn a_refresh_replaces_the_previous_reading_rather_than_adding_to_it() {
        let stats = CaptureStats::default();

        stats.store(&pcap::Stat {
            received: 500,
            dropped: 4,
            if_dropped: 0,
        });
        stats.store(&pcap::Stat {
            received: 900,
            dropped: 9,
            if_dropped: 0,
        });

        assert_eq!(
            stats.snapshot(),
            CaptureCounts {
                received: 900,
                dropped: 9,
                if_dropped: 0,
                stopped_early: 0,
            }
        );
    }

    /// The flag is read while the guard is alive, as every scanner reads it: the counts
    /// go into the scan's report before the transport is dropped. So a reader that
    /// panics must record it before the guard joins it, and the counters here are the
    /// guard's own, with no clone held outside to read them through.
    #[test]
    fn a_panicked_reader_is_visible_in_the_counts_while_the_guard_is_alive() {
        let counters = Arc::new(CaptureStats::default());
        let handle = spawn_reader("test0", Arc::clone(&counters), |_| {
            panic!("a reader died the way a defect kills one")
        })
        .expect("a thread starts");
        let guard = CaptureGuard {
            stop: Arc::new(AtomicBool::new(false)),
            handles: vec![handle],
            stats: vec![counters],
            _held_back: None,
        };

        while !guard.handles[0].is_finished() {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(
            guard.counts().expect("one capture").stopped_early,
            1,
            "a dead reader is reported only once nobody is reading any more"
        );
    }

    /// A reader that ended cleanly is not reported as having stopped early.
    #[test]
    fn a_capture_thread_that_finished_is_not_recorded_as_stopping_early() {
        let counters = Arc::new(CaptureStats::default());
        let guard = CaptureGuard {
            stop: Arc::new(AtomicBool::new(false)),
            handles: vec![
                spawn_reader("test0", Arc::clone(&counters), |_| {}).expect("a thread starts"),
            ],
            stats: vec![Arc::clone(&counters)],
            _held_back: None,
        };

        drop(guard);
        assert!(!counters.stopped_early.load(Ordering::Relaxed));
    }

    /// Captures opened in a table the scan's connections were sized against take the
    /// descriptors they hold out of what those connections may hold, for as long as
    /// they are open.
    ///
    /// Forty free of 64 when the scan starts leaves its connections the whole gate.
    /// Twenty-eight links' captures then take twenty-eight of those forty, and a gate
    /// still promising thirty-two would send connections past the table's room to wait
    /// out their patience and be filed unasked.
    #[cfg(unix)]
    #[test]
    fn a_capture_holds_back_the_connections_its_links_took_the_room_of() {
        use crate::system::descriptors::testing::{exhaust, in_a_process_of_its_own};
        use crate::system::descriptors::{OPENED_WHILE_RUNNING, gate, hold_back};

        if !in_a_process_of_its_own(
            module_path!(),
            "a_capture_holds_back_the_connections_its_links_took_the_room_of",
        ) {
            return;
        }
        let mut held = exhaust(64);
        held.truncate(held.len() - 40);
        let whole = gate().available_permits();
        let scan = hold_back();
        let at_start = gate().available_permits();

        let links: Vec<std::fs::File> = (0..28)
            .map(|_| std::fs::File::open("/dev/null").expect("a descriptor for a link"))
            .collect();
        let guard = CaptureGuard::running(Arc::new(AtomicBool::new(true)), Vec::new(), Vec::new());
        let capturing = gate().available_permits();
        drop(guard);
        let closed = gate().available_permits();
        drop((links, scan, held));

        assert_eq!(
            (whole, at_start),
            (32, 32),
            "the table had room for the gate"
        );
        assert_eq!(
            capturing,
            40 - 28 - OPENED_WHILE_RUNNING,
            "the connections are let hold what the captures left"
        );
        assert_eq!(closed, whole, "and the captures closing gives it back");
    }
}
