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
//! On BSD-derived systems (macOS included), the kernel does **not** deliver
//! TCP or UDP segments to raw IP sockets - those protocols are reserved to
//! the in-kernel stack - so the Layer-4 raw socket that works on Linux
//! receives nothing at all. Capturing at the data-link layer via `libpcap`
//! sidesteps that: BPF (macOS/BSD), `AF_PACKET` (Linux), and Npcap (Windows)
//! all see inbound frames before the stack decides what to do with them, so
//! one capture path behaves identically everywhere.
//!
//! Each interface is opened with a compiled BPF filter so the *kernel* drops
//! everything except the packets a scan actually cares about - only matching
//! frames are ever copied into userspace. Captures run on dedicated OS
//! threads (the `libpcap` read is blocking) and funnel parsed
//! `(segment, source_ip)` pairs into a single Tokio channel, so async scan
//! code consumes one merged stream regardless of how many interfaces are live.
//!
//! [`CaptureOptions`] is how a capture is asked for. Which frames the kernel
//! admits, how much of each one it keeps, and whether it accepts traffic
//! addressed elsewhere are three settings that have to be chosen together, and
//! [`CaptureOptions::for_replies`] is the choice a scanner should take unchanged.

use std::net::IpAddr;
use std::ops::ControlFlow;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pcap::{Active, Capture, Device};
use pnet_packet::ip::IpNextHeaderProtocol;
#[cfg(not(windows))]
use std::os::unix::io::AsRawFd;
use tokio::sync::mpsc;

use crate::model::capture::{CaptureCounts, IpObservation};
use crate::model::ip::scoped::Zone;
use crate::protocols::ethernet::VLAN_TAG_LEN;
use crate::protocols::sizes::{ETH_HDR_LEN, IP_V6_HDR_LEN};
use crate::transport::frame::{self, LinkType};
use crate::{error, info, warn};
use pnet_base::MacAddr;

/// Largest capture a scan's receive path ever needs: a reply is a bare TCP/UDP
/// segment, but snapping generously costs nothing against a filter this narrow
/// and avoids ever truncating one.
pub const REPLY_SNAP_LEN: u32 = 65_535;

/// The shortest snapshot length worth opening a capture at.
///
/// Derived rather than chosen: the deepest header stack this crate reads before
/// it has an answer is an Ethernet header with two VLAN tags, the larger of the
/// two IP headers, and a TCP header with its full options. A capture snapped
/// below that truncates the reply it was opened for, and reports the resulting
/// silence as a network that said nothing.
///
/// It is a floor and not a default. [`CaptureOptions::with_snaplen`] raises
/// anything lower to it, which is also what keeps a zero from reaching
/// `libpcap`, whose treatment of one is undefined by its own manual page.
pub const MIN_SNAP_LEN: u32 =
    (ETH_HDR_LEN + 2 * VLAN_TAG_LEN + IP_V6_HDR_LEN + TCP_MAX_HDR_LEN) as u32;

/// A TCP header with the full forty bytes of options its data offset can
/// describe.
const TCP_MAX_HDR_LEN: usize = 60;

// Both halves of the floor's argument, held at compile time because both sides
// are constants: a test could only restate what the compiler already knows, and
// a build is where a wrong one should stop.
const _: () = assert!(
    MIN_SNAP_LEN as usize >= ETH_HDR_LEN + 2 * VLAN_TAG_LEN + IP_V6_HDR_LEN + TCP_MAX_HDR_LEN,
    "the snapshot floor is below a header stack this crate parses"
);
const _: () = assert!(
    REPLY_SNAP_LEN > MIN_SNAP_LEN,
    "the snapshot length a scanner takes unchanged is below the floor"
);

/// How a capture is opened: what the kernel admits, how much of each frame it
/// keeps, and whose traffic it accepts at all.
///
/// [`for_replies`](Self::for_replies) is this engine's whole opinion for a
/// scan's receive path, and a scanner should take it and change nothing. The
/// builders exist for a caller reading traffic the scan did not cause, whose
/// answers differ on every setting here.
///
/// # Why a value rather than three arguments
///
/// Two of these were previously fixed and one was never chosen at all — a
/// constant for the snapshot length, `libpcap`'s own default for the buffer, and
/// promiscuity left wherever the library happened to leave it. That was
/// defensible while one caller existed with one set of needs.
///
/// It stops being defensible with a second, because the settings are not
/// independent. A wide filter with a generous snapshot length and a default
/// buffer is a capture that discards most of what it admits, and the three have
/// to be decided together or not at all.
///
/// The snapshot length is also the only place a limit on **what this process
/// reads of other people's traffic** can be enforced by the kernel rather than
/// by discipline, which is a property worth having a type to hang on.
#[must_use]
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// A `libpcap` filter expression, in `tcpdump` syntax, compiled to a kernel
    /// BPF program. Only matching frames are copied into this process.
    filter: String,
    /// How many bytes of each matching frame to keep. The rest is discarded by
    /// the kernel and never reaches this process.
    snaplen: u32,
    /// Whether to accept frames not addressed to this host.
    promiscuous: bool,
    /// How much the kernel may hold for this capture before it starts
    /// discarding. `None` leaves `libpcap`'s own default in place.
    buffer_bytes: Option<u32>,
}

impl CaptureOptions {
    /// A capture of what was addressed to **this host**: the replies to probes
    /// it sent.
    ///
    /// **Not promiscuous**, which is the whole of the difference from
    /// [`for_link_traffic`](Self::for_link_traffic). A reply to a probe this
    /// host sent comes back to this host, so accepting frames addressed
    /// elsewhere adds only other people's traffic — which fills the buffer this
    /// scan's own answers have to fit in.
    ///
    /// **The whole frame is kept** ([`REPLY_SNAP_LEN`]). A reply is small and
    /// the filter is narrow, so snapping generously costs almost nothing where
    /// truncating one would cost an observation.
    ///
    /// **The kernel's default buffer.** These arrivals are bounded by the probes
    /// this host sent, so there is a rate above which nothing comes, and the
    /// default has been sufficient for it.
    pub fn for_replies(filter: impl Into<String>) -> Self {
        Self {
            filter: filter.into(),
            snaplen: REPLY_SNAP_LEN,
            promiscuous: false,
            buffer_bytes: None,
        }
    }

    /// A capture of everything the link carries that `filter` admits, whoever it
    /// was addressed to.
    ///
    /// **Promiscuous**, which is what separates this from
    /// [`for_replies`](Self::for_replies), and it is not a preference. Several
    /// things a segment sweep concludes are carried in frames addressed to
    /// somebody else: a DHCP server's answer is often unicast to the client that
    /// asked, and a multicast group this host never joined may be filtered out
    /// by the interface before `libpcap` is offered it at all.
    ///
    /// The narrowing is done by `filter`, in the kernel, which is the better
    /// instrument for it: promiscuity decides what the interface hands up, and
    /// the filter decides what is copied into this process. Widening the first
    /// while keeping the second tight is how a capture sees what it needs and
    /// carries what it does not need nowhere at all.
    pub fn for_link_traffic(filter: impl Into<String>) -> Self {
        Self {
            promiscuous: true,
            ..Self::for_replies(filter)
        }
    }

    /// Keeps only the first `bytes` of each frame, discarding the rest in the
    /// kernel.
    ///
    /// Two things at once, which is why it is worth setting deliberately. It
    /// bounds the copying a busy link costs this process, and it bounds what
    /// this process can see of a payload it has no business reading — the
    /// second being a limit the kernel enforces rather than one userspace
    /// promises to keep.
    ///
    /// Raised to [`MIN_SNAP_LEN`] where it is lower, since below that a capture
    /// cannot see the headers it exists to read and every frame arrives as a
    /// truncation. `libpcap` does not define what a snapshot length of zero
    /// means — the manual page does not say, and it has not meant the same thing
    /// across versions — so a setting whose whole argument is that the kernel
    /// enforces it is not handed over at a value the kernel is free to
    /// reinterpret.
    pub fn with_snaplen(mut self, bytes: u32) -> Self {
        self.snaplen = bytes.max(MIN_SNAP_LEN);
        self
    }

    /// Accepts frames not addressed to this host.
    ///
    /// What the interface would otherwise discard before `libpcap` saw it. On a
    /// switched network this admits broadcast and multicast in full and unicast
    /// only where the switch happens to forward it, so it widens what *can* be
    /// seen without promising that anything will be.
    pub fn with_promiscuous(mut self, promiscuous: bool) -> Self {
        self.promiscuous = promiscuous;
        self
    }

    /// Lets the kernel hold `bytes` for this capture before it starts
    /// discarding.
    ///
    /// The buffer is what absorbs the gap between a burst arriving and this
    /// process reading it, so it is the setting that decides whether a spike
    /// becomes a `dropped` count. Worth raising for any capture whose arrival
    /// rate is set by the network rather than by probes this host sent.
    pub fn with_buffer_bytes(mut self, bytes: u32) -> Self {
        self.buffer_bytes = Some(bytes);
        self
    }
}

/// How long a reader thread waits for a frame before looping back to check the
/// stop flag. Bounds shutdown latency without busy-looping.
///
/// On Unix this is the timeout of the [`wait_readable`] poll rather than
/// `libpcap`'s own read timeout, which cannot be relied on: see [`open`].
const READ_TIMEOUT_MS: i32 = 100;

/// How many frames a reader may forward between refreshes of its kernel
/// counters.
///
/// A scanner reads [`CaptureCounts`] while its capture threads are still
/// running, so the counters have to be current mid-run rather than only at
/// shutdown. Refreshing on the idle path alone would miss the one case worth
/// measuring: while frames are arriving faster than they are read the loop
/// never goes idle, and that is precisely when a buffer overflows.
const STATS_EVERY_FRAMES: u32 = 128;

/// How long a reader thread waits before offering a frame again, once the
/// consumer's queue is full.
///
/// Short enough that a consumer catching its breath is not made to wait on this
/// thread, and long enough that a genuinely overrun capture is not spinning a
/// core while the kernel buffer does the work of absorbing the burst.
const QUEUE_FULL_PAUSE: Duration = Duration::from_millis(1);

/// One reply lifted off the wire: the Layer-4 segment, who sent it, which
/// protocol it is, and what its IP header said on the way past.
///
/// The protocol is carried rather than inferred because a filter may admit
/// more than one - a UDP port scan watches for both direct UDP replies and the
/// ICMP errors that answer them - and Layer-4 headers are not self-describing
/// enough to tell apart after the fact (see [`frame::IpSegment`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedSegment {
    /// The address the reply came from.
    pub source: IpAddr,
    /// The protocol [`bytes`](Self::bytes) should be parsed as.
    pub protocol: IpNextHeaderProtocol,
    /// The Layer-4 segment, link and IP headers already stripped.
    pub bytes: Vec<u8>,
    /// What the IP header this segment arrived under said about the stack that
    /// sent it, or `None` if there was no IP header to read.
    ///
    /// `None` is not "nothing notable was in it". It means this segment did not
    /// come off a wire at all: a synthetic receive stream built through
    /// `ProbeTransport::from_parts` hands over Layer-4 bytes it composed
    /// itself, and there is no header behind them to have observed. Reporting a
    /// default TTL and a zero identifier for one would claim a measurement
    /// nobody took, which is the same reason
    /// [`CaptureGuard::counts`](CaptureGuard::counts) is optional rather than
    /// zero.
    ///
    /// A test that wants to exercise something reading these can of course
    /// supply one — the point is only that it has to say so.
    pub observation: Option<IpObservation>,

    /// The hardware address the frame carrying this segment came from, where the
    /// link had one.
    ///
    /// Carried because it is the only thing here that can say whether a reply
    /// came from the host it claims to. Anything answering in a host's place uses
    /// that host's IP address, so [`source`](Self::source) cannot tell a genuine
    /// answer from an intercepted one; this can, on an on-link segment.
    ///
    /// **Not a vendor lookup.** An off-link reply carries the last-hop router's
    /// address and looks no different from here. See
    /// [`frame::source_mac`] for the full argument.
    ///
    /// `None` on a tunnel, loopback or raw-IP link, which prepend no addresses,
    /// and on a synthetic stream. Never "the sender had none".
    pub source_mac: Option<MacAddr>,
}

impl CapturedSegment {
    /// A segment with no IP header behind it, for a receive stream that composed
    /// its Layer-4 bytes rather than capturing them.
    ///
    /// Exists so the ordinary synthetic case is one call rather than a struct
    /// literal ending in `observation: None`, and so that adding a further
    /// observed field later does not break every test that builds one.
    pub fn synthetic(source: IpAddr, protocol: IpNextHeaderProtocol, bytes: Vec<u8>) -> Self {
        Self {
            source,
            protocol,
            bytes,
            observation: None,
            source_mac: None,
        }
    }
}

/// The parsed receive stream produced by a running capture: [`CapturedSegment`]s
/// from every captured interface, interleaved in arrival order.
///
/// Bounded, as [`FrameStream`] is and for the same reason. [`segments`]
/// documents where the traffic that fills it comes from.
pub type CaptureStream = mpsc::Receiver<CapturedSegment>;

/// One frame as it came off a link, with nothing stripped.
///
/// The counterpart to [`CapturedSegment`], and the shape to read when the answer
/// is not inside a Layer-4 segment. An ARP exchange, a neighbour advertisement,
/// a switch announcing itself and an 802.1Q tag all live below the point where
/// [`CapturedSegment`] begins, and by the time one of those exists the evidence
/// is gone.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedFrame {
    /// The link this frame arrived on.
    ///
    /// Carried because a great deal of what a frame proves is only true of one
    /// segment. An IPv6 link-local names a different machine on every link, a
    /// switch announces itself to the port it is announcing *about*, and a VLAN
    /// tag means nothing without the trunk it was read from. A capture merges
    /// every link into one stream, so without this the merge would be lossy in
    /// exactly the cases that matter.
    pub zone: Zone,

    /// How [`bytes`](Self::bytes) is framed, so a reader knows what it is
    /// looking at before it looks.
    pub link: LinkType,

    /// The frame, link header included.
    ///
    /// **Possibly truncated**, to whatever [`CaptureOptions::with_snaplen`] the
    /// capture was opened with. That is deliberate — it is how a capture is
    /// stopped from reading more of somebody's traffic than it has any business
    /// reading — and it means a reader must treat a short frame as ordinary
    /// rather than as corrupt. Every parser in [`crate::protocols`] already
    /// declines rather than guessing, which is the property this relies on.
    pub bytes: Vec<u8>,

    /// When the kernel timestamped the frame.
    pub observed_at: SystemTime,
}

/// The whole-frame receive stream produced by [`frames`]: [`CapturedFrame`]s
/// from every captured link, interleaved in arrival order.
///
/// Bounded, unlike [`CaptureStream`]. What arrives here is set by the network
/// rather than by probes this host sent, so there is no rate at which the
/// consumer is guaranteed to keep up, and an unbounded queue would answer that
/// by growing until the process died. [`frames`] documents what happens instead.
pub type FrameStream = mpsc::Receiver<CapturedFrame>;

/// One capture's counters, written by its reader thread and read by whoever
/// holds the [`CaptureGuard`].
///
/// Kept as atomics rather than behind a lock because the writer is a capture
/// thread in its hot loop: a reader that observes a slightly stale count draws
/// the same conclusion from it, while a reader lock in that loop would perturb
/// the very timing being measured.
#[derive(Debug, Default)]
struct CaptureStats {
    received: AtomicU64,
    dropped: AtomicU64,
    if_dropped: AtomicU64,
    /// Whether this reader ended before it was told to.
    ///
    /// A flag here and a count in [`CaptureCounts`], because one capture either
    /// lasted or it did not, and what a report wants to know is how many of them
    /// did.
    stopped_early: AtomicBool,
}

impl CaptureStats {
    /// Replaces the counters with what `libpcap` currently reports. Values are
    /// cumulative from the start of the capture, so storing rather than adding
    /// is what keeps them from double-counting.
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

/// Keeps a set of live per-interface captures running for as long as it's
/// held. Dropping it signals every reader thread to stop and waits for each,
/// so no capture thread outlives the guard.
///
/// **Dropping blocks**, for one read timeout, and the flag is what bounds it. A
/// thread waiting for room in a full queue reads the flag too, so a guard
/// dropped while a consumer still holds the receiver and has stopped draining
/// it comes back on the same schedule as any other.
///
/// A guard is normally dropped inside the scan task, which is to say on a
/// runtime worker, so on a multi-threaded runtime the wait is handed to
/// [`block_in_place`](tokio::task::block_in_place) and the worker is released to
/// run other tasks meanwhile. A single-threaded runtime has no other worker to
/// hand it to, and a caller outside a runtime is simply blocking their own
/// thread.
///
/// This is deliberately separate from the [`CaptureStream`] it feeds, so a
/// consumer can own the receiver directly (borrowing it mutably in a
/// `select!`) while the guard sits beside it keeping the threads alive.
pub struct CaptureGuard {
    stop: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
    /// One set of counters per live capture, shared with the thread reading it.
    stats: Vec<Arc<CaptureStats>>,
}

impl Drop for CaptureGuard {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);

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
    /// A guard owning no capture threads, for a transport whose receive stream
    /// is supplied directly rather than read off an interface. Reached from
    /// outside the crate only through [`ProbeTransport::from_parts`], which
    /// builds one on the caller's behalf.
    ///
    /// [`ProbeTransport::from_parts`]: crate::transport::probe::ProbeTransport::from_parts
    #[cfg(any(test, feature = "test-support"))]
    pub(crate) fn noop() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
            stats: Vec::new(),
        }
    }

    /// The kernel counters of every capture this guard keeps alive, summed.
    ///
    /// `None` when there is no capture at all - a transport fed a synthetic
    /// receive stream has no kernel buffer to overflow, and reporting zero
    /// drops for it would claim a clean receive path was measured when nothing
    /// was.
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
/// One variant, because there is one way this fails. An interface that cannot be
/// captured is skipped and logged rather than failing the scan — a host has
/// several, most of them irrelevant to any given probe, and refusing to scan
/// because a virtual bridge declined would be wrong. Only *every* interface
/// failing leaves the scan with nowhere to hear an answer, and that is this.
///
/// `#[non_exhaustive]` because the capture layer is where new platform-specific
/// failures show up first.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// No interface could be captured, so no reply could ever be heard. Almost
    /// always missing privileges: opening a capture needs root on every platform
    /// this engine supports.
    #[error(
        "no interface could be captured for replies, so no answer could be heard \
         (opening a capture needs root)"
    )]
    NoInterface,
    /// Every link opened and not one of them could be given a reader thread.
    ///
    /// A runtime condition rather than a mistake: a process near its thread
    /// limit, or a cgroup that caps them. Separate from
    /// [`NoInterface`](Self::NoInterface) because the remedy is different and
    /// naming privileges here would send a reader looking in the wrong place.
    #[error("captured {opened} link(s) but could not start a reader for any of them: {source}")]
    NoReader {
        /// How many links opened before the threads were asked for.
        opened: usize,
        /// What the last spawn refused with.
        #[source]
        source: std::io::Error,
    },
    /// A link carries frames this crate cannot strip down to an IP packet.
    ///
    /// Not a failure to open it: the capture came up and its data-link type is
    /// one nothing here parses. Skipped rather than misread, because guessing at
    /// a framing is how a scanner reports a network that is not there.
    #[error("{interface} carries data-link type {dlt}, which nothing here parses")]
    UnsupportedLinkType {
        /// The link that was opened.
        interface: String,
        /// The `libpcap` data-link type it reported.
        dlt: i32,
    },

    /// The filter expression would not compile to a BPF program.
    ///
    /// A mistake in the expression rather than anything about the host, and the
    /// expression is named because it is the thing to look at.
    #[error("the filter `{filter}` would not compile: {source}")]
    Filter {
        /// The expression that was rejected.
        filter: String,
        /// What `libpcap` said.
        #[source]
        source: pcap::Error,
    },

    /// One named link could not be opened. Unlike `NoInterface` this names the
    /// link, because a caller asked for that one in particular and there is
    /// nothing else to fall back to.
    #[error("{interface} could not be opened: {source}")]
    Open {
        /// The link that refused.
        interface: String,
        /// What `libpcap` said.
        #[source]
        source: pcap::Error,
    },
}

/// Opens a filtered capture on each named link and starts reading, parsing
/// every admitted frame down to the Layer-4 segment a scanner reads.
///
/// **Frames that are not IP are dropped here**, because the segment is what a
/// scanner reads and there is none behind an ARP frame. A caller that wants
/// those is asking a different question and wants the whole frame — see
/// [`frames`], which this is otherwise the twin of.
///
/// # The stream is bounded, and has to be
///
/// Most of what arrives is bounded by what this host sent: a reply exists
/// because a probe was emitted, and the scanner emitting them is the same task
/// reading this. The rest is not, and the filters say so themselves. Only
/// [`ProbeKind::UdpResolve`](crate::transport::probe::ProbeKind) narrows to this
/// scan in both address families. A SYN sweep admits every IPv6 TCP segment
/// because `tcp[tcpflags]` will not compile over a next-header chain, and the
/// three kinds that read ICMP errors admit `icmp or icmp6` whole because an
/// error names no ports of its own. Each of those is the right trade and each
/// leaves a rate the network sets rather than the scan.
///
/// So `queue_depth` bounds what may wait, exactly as it does for [`frames`], and
/// a full queue stalls the reader rather than discarding: the kernel buffer
/// takes up the slack, `libpcap` counts what it drops, and the loss lands in
/// [`CaptureCounts::dropped`] where a report already carries it.
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
                protocol: parsed.protocol,
                bytes: parsed.payload.to_vec(),
                observation: Some(parsed.observation),
                source_mac,
            };

            // Waits rather than drops, for the reason `frames` gives.
            loop {
                match tx.try_send(segment) {
                    Ok(()) => return ControlFlow::Continue(()),
                    Err(mpsc::error::TrySendError::Closed(_)) => return ControlFlow::Break(()),
                    Err(mpsc::error::TrySendError::Full(returned)) => {
                        // A guard being dropped is not a reason to keep waiting
                        // for room, and the join it is about to do would wait
                        // on this thread. See `CaptureGuard`.
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

/// Opens a filtered capture on each named link and starts reading, forwarding
/// every admitted frame whole.
///
/// The twin of [`segments`], and the one to reach for when the answer is not in
/// a Layer-4 segment: an ARP exchange, a neighbour advertisement, a switch
/// announcing itself, the VLAN a frame was tagged with, or the hardware address
/// behind any of them. Each frame arrives with the link it came off, so a
/// finding that only means something on one segment can say which.
///
/// `queue_depth` bounds how many frames may wait for the consumer at once.
/// Multiplied by [`CaptureOptions::with_snaplen`] it is also the memory this
/// costs, which is the reason it is a number the caller states rather than one
/// this module picks.
///
/// # A full queue stalls the reader rather than dropping
///
/// When the consumer falls behind, the reader thread waits instead of discarding
/// the frame it is holding. The kernel buffer then takes up the slack, and when
/// that fills, `libpcap` counts what it discards — so the loss lands in
/// [`CaptureCounts::dropped`], which a report already carries and a reader
/// already knows how to interpret.
///
/// Discarding here instead would be a fourth kind of loss, counted nowhere and
/// indistinguishable in the record from a network that had nothing to say. The
/// stall makes the existing counter tell the whole truth.
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
            };

            // Waits rather than drops; see this function's documentation for why
            // the loss belongs in the kernel's counter and not in a new one.
            loop {
                match tx.try_send(frame) {
                    Ok(()) => return ControlFlow::Continue(()),
                    Err(mpsc::error::TrySendError::Closed(_)) => return ControlFlow::Break(()),
                    Err(mpsc::error::TrySendError::Full(returned)) => {
                        // A guard being dropped is not a reason to keep waiting
                        // for room, and the join it is about to do would wait
                        // on this thread. See `CaptureGuard`.
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
/// capture, and hands back the guard that keeps them alive.
///
/// `deliver_for` builds the per-link closure that decides what to do with each
/// frame, which is the whole of the difference between [`segments`] and
/// [`frames`]. Everything else — which failures are survivable, how threads are
/// named and stopped, when counters refresh — is identical for both and lives
/// here so that it cannot come to differ.
///
/// Interfaces that fail to open, or whose data-link type this crate cannot
/// parse, are logged and skipped rather than aborting the whole capture: a host
/// has many, most of them irrelevant to any given capture, and refusing because
/// a virtual bridge declined would be wrong. Only *every* link failing is an
/// error, since a capture with no link is a receive path that can never hear
/// anything.
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

    // Named here and counted, rather than a line per interface as this once
    // logged. A scan opens a capture on every interface that is up — twenty-six
    // on an ordinary laptop with a VPN and a hypervisor — and does it once per
    // transport, so the per-interface line put a hundred lines of scaffolding
    // between the caller and their results at the *first* level of detail. The
    // count is what a person is checking at `-v` ("did it capture at all, and on
    // roughly the right number of things"); which interface got which filter is
    // a question for `-vvv`, and it is still there when asked.
    let mut opened = 0usize;
    // Why the last reader thread refused to start, for the case where none did.
    let mut unstarted: Option<std::io::Error> = None;

    for zone in links {
        let name = zone.name();
        match open(name, options) {
            Ok((capture, link)) => {
                info!(verbosity = 3, "capturing on {name} (link type {link:?})");
                opened += 1;

                let stop = stop.clone();
                let deliver = deliver_for(zone, link, stop.clone());
                let counters = Arc::new(CaptureStats::default());
                stats.push(counters.clone());
                let name = name.to_owned();

                match thread::Builder::new()
                    .name(format!("capture-{name}"))
                    .spawn(move || reader_loop(capture, &stop, &name, &counters, deliver))
                {
                    Ok(handle) => handles.push(handle),
                    // The same trade the open failure above takes. A host near
                    // its thread limit still captures on the links it managed,
                    // and only losing every one of them is an error.
                    Err(e) => {
                        warn!("no reader thread for {}: {e}", zone.name());
                        stats.pop();
                        unstarted = Some(e);
                    }
                }
            }
            Err(e) => warn!("skipping capture on {name}: {e}"),
        }
    }

    if handles.is_empty() {
        return Err(match unstarted {
            Some(source) => CaptureError::NoReader { opened, source },
            None => CaptureError::NoInterface,
        });
    }

    info!(
        verbosity = 1,
        "capturing on {opened} interface(s) with filter: {}", options.filter,
    );

    Ok(CaptureGuard {
        stop,
        handles,
        stats,
    })
}

/// When the kernel says it saw this frame.
///
/// Wall-clock rather than measured elapsed time, because the question it answers
/// is "when was this host last heard from", which a reader places against
/// everything else in the record. A frame whose timestamp cannot be represented
/// is stamped with the epoch rather than dropped: the frame is still evidence,
/// and losing it over a clock would be the wrong trade.
fn timestamp_of(packet: &pcap::Packet<'_>) -> SystemTime {
    let seconds = u64::try_from(packet.header.ts.tv_sec).unwrap_or(0);
    let micros = u32::try_from(packet.header.ts.tv_usec).unwrap_or(0);
    UNIX_EPOCH + Duration::new(seconds, micros.saturating_mul(1_000))
}

/// Opens and activates a single filtered capture, returning it alongside the
/// [`LinkType`] its frames must be parsed as.
///
/// On Unix the capture is put into non-blocking mode and the reader waits on the
/// descriptor itself. `libpcap`'s read timeout is not a usable substitute:
/// Linux's memory-mapped `TPACKET` path treats it only as the timeout of its own
/// internal `poll`, and loops back to poll again instead of returning to the
/// caller, so a blocking read on an interface seeing no matching frames never
/// returns and the stop flag is never observed. BSD's `BPF` (macOS) does return
/// on timeout, but relying on that would leave Linux broken.
fn open(name: &str, options: &CaptureOptions) -> Result<(Capture<Active>, LinkType), CaptureError> {
    let refused = |source: pcap::Error| CaptureError::Open {
        interface: name.to_owned(),
        source,
    };

    let device = Device::from(name);
    let mut inactive = Capture::from_device(device)
        .map_err(refused)?
        .immediate_mode(true)
        .promisc(options.promiscuous)
        .snaplen(saturating_i32(options.snaplen))
        .timeout(READ_TIMEOUT_MS);

    // Left alone unless asked for, so that not choosing a buffer size keeps
    // whatever the platform's `libpcap` decided rather than this crate picking a
    // number for every capture on every operating system it runs on.
    if let Some(bytes) = options.buffer_bytes {
        inactive = inactive.buffer_size(saturating_i32(bytes));
    }

    let capture = inactive.open().map_err(refused)?;

    #[cfg(not(windows))]
    let capture = capture.setnonblock().map_err(refused)?;

    let mut capture = capture;
    let link = LinkType::from_dlt(capture.get_datalink().0);
    if let LinkType::Unsupported(dlt) = link {
        return Err(CaptureError::UnsupportedLinkType {
            interface: name.to_owned(),
            dlt,
        });
    }

    capture
        .filter(&options.filter, true)
        .map_err(|source| CaptureError::Filter {
            filter: options.filter.clone(),
            source,
        })?;

    Ok((capture, link))
}

/// Narrows a byte count to the signed width `libpcap` takes, saturating rather
/// than wrapping.
///
/// Both settings this converts are sizes, and both are meaningless as negative
/// numbers — a wrapped snapshot length is a capture that keeps nothing, which
/// would read as a quiet network rather than as a bad argument. The `u32` on
/// [`CaptureOptions`] is the honest type for the engine to speak; this is the
/// one place the library's `i32` is met.
fn saturating_i32(bytes: u32) -> i32 {
    i32::try_from(bytes).unwrap_or(i32::MAX)
}

/// Read loop for one capture: hand every admitted frame to `deliver` until it
/// asks to stop, the stop flag is set, or the capture fails. Having no frame
/// ready is the normal idle case, not an error.
///
/// `deliver` is given the whole `libpcap` packet — its bytes and the header
/// carrying the kernel's timestamp — and says whether to carry on. Both outputs
/// this module offers are one of these, which is the point: the shutdown
/// discipline, the poll, and the counter cadence are subtle enough that having
/// two copies of them would mean having one of them wrong.
///
/// The loop also keeps `counters` current, since what this thread fails to read
/// in time is invisible everywhere else: a frame the kernel discards for want of
/// buffer space never reaches the channel, so no downstream counter can miss it.
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
        // Whether this iteration read a frame, decided inside the match and
        // acted on after it: the packet borrows the capture, and refreshing the
        // counters needs it back.
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
                // Recorded as well as logged, where the link is actually lost.
                // This thread is the only thing reading this interface, so
                // ending here makes it deaf for the rest of the scan, and every
                // reply that would have arrived on it is silence a scanner
                // cannot tell from a host that did not answer. That is the loss
                // `CaptureCounts` exists to carry, and a log line is not the
                // record.
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

        // Idle is also the cheapest moment to refresh: nothing is waiting on
        // this thread, and a scan that ends quietly gets a final count for free.
        if !read_frame {
            refresh(&mut capture, counters);
            since_refresh = 0;
            #[cfg(not(windows))]
            wait_readable(fd);
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

/// Whether a capture ending on `error` leaves the link deaf, or merely reached
/// the end of what it had to give.
///
/// The distinction is the whole of what [`CaptureCounts::stopped_early`] means,
/// and it is a function so that it can be stated and tested rather than living
/// in the shape of a match nothing can reach. A live capture never runs out of
/// packets, so `NoMorePackets` is a savefile ending normally; everything else
/// is a receive path that stopped part-way through a scan.
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
/// A failure is not reported. `pcap_stats` is unsupported on some capture
/// sources, so a thread that cannot answer would otherwise log once per refresh
/// for the life of the scan; the counters simply stay where they were, and a
/// stalled count is visible as such next to a running scan.
fn refresh(capture: &mut Capture<Active>, counters: &CaptureStats) {
    if let Ok(stat) = capture.stats() {
        counters.store(&stat);
    }
}

/// Waits for `fd` to have a frame ready, giving up after [`READ_TIMEOUT_MS`] so
/// the caller can re-check its stop flag. Poll failures are not reported: the
/// caller's next read reports anything genuinely wrong, and an interrupted poll
/// simply costs one extra loop.
#[cfg(not(windows))]
fn wait_readable(fd: std::os::unix::io::RawFd) {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    // SAFETY: `poll_fd` is a single initialized `pollfd` and the count says so;
    // `poll` reads it and writes only `revents`.
    unsafe { libc::poll(&mut poll_fd, 1, READ_TIMEOUT_MS) };
}

/// A handle for putting whole frames on a link.
///
/// **The send half of the same library the receive half already uses.** It was
/// `pnet_datalink`'s, which meant two libraries open on one interface for one
/// scan: a `pnet` channel whose receiver was discarded, and a `pcap` capture
/// that replaced it. The discarded receiver was a kernel buffer nothing drained,
/// and the comment saying so was in the code for as long as the arrangement was.
///
/// A separate handle from the reading one, because a capture cannot be read and
/// written through the same borrow while a reader thread is parked in
/// `next_packet`. What it is not is a separate *library*.
pub struct FrameSender {
    capture: Capture<Active>,
}

impl FrameSender {
    /// Opens a send-only handle on `link`.
    ///
    /// The filter is one that cannot match. This handle exists to write, and a
    /// capture with no filter at all would fill a kernel buffer nobody reads —
    /// which is the defect the arrangement this replaces was documented as
    /// having. `less 0` asks for frames shorter than nothing.
    pub fn open(link: &str) -> Result<Self, CaptureError> {
        let mut capture = Capture::from_device(Device::from(link))
            .and_then(|inactive| inactive.snaplen(1).timeout(1).open())
            .map_err(|source| CaptureError::Open {
                interface: link.to_owned(),
                source,
            })?;

        capture
            .filter("less 0", true)
            .map_err(|source| CaptureError::Open {
                interface: link.to_owned(),
                source,
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
/// A trait rather than the concrete sender for one reason: it is the seam a test
/// drives a scanner through, the way [`FrameStream`] is on the receive side. A
/// fake segment implements this, observes what a scanner emits, and answers on
/// the stream — with no interface and no privileges involved.
pub trait FrameSink: Send {
    /// Puts `frame` on the wire whole, link header included.
    ///
    /// The error is a string because there is nothing a caller can do with it
    /// but report it, and the two libraries that have ever implemented this
    /// disagree about everything else. What matters at the call site is that a
    /// failure means the frame did not leave.
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String>;
}

/// One link, opened for both directions and driven by a single thread.
///
/// The shape a request-and-wait exchange wants: put a frame on the wire, then
/// read until the answer arrives or the deadline passes. Both halves borrow the
/// same handle mutably, which is exactly why this is one type and not a pair —
/// and why it is not what [`frames`] gives a scanner, whose reader lives on its
/// own thread and cannot share a borrow with anybody.
///
/// The filter is the caller's, for the reason it always is here: what a frame is
/// worth is decided by whoever reads it.
pub struct FrameChannel {
    capture: Capture<Active>,
}

impl FrameChannel {
    /// Opens `link` for sending and receiving, admitting what `filter` admits.
    ///
    /// `read_timeout` bounds how long [`next_frame`](Self::next_frame) waits, so
    /// a caller with a deadline can honour it rather than parking until a frame
    /// happens to arrive.
    pub fn open(
        link: &str,
        filter: &str,
        read_timeout: std::time::Duration,
    ) -> Result<Self, CaptureError> {
        let millis = i32::try_from(read_timeout.as_millis()).unwrap_or(i32::MAX);
        let mut capture = Capture::from_device(Device::from(link))
            .and_then(|inactive| {
                inactive
                    .immediate_mode(true)
                    .snaplen(saturating_i32(REPLY_SNAP_LEN))
                    .timeout(millis)
                    .open()
            })
            .map_err(|source| CaptureError::Open {
                interface: link.to_owned(),
                source,
            })?;

        capture
            .filter(filter, true)
            .map_err(|source| CaptureError::Open {
                interface: link.to_owned(),
                source,
            })?;

        Ok(Self { capture })
    }

    /// The next frame the filter admitted, or `None` on a read timeout.
    ///
    /// `None` is not the end of anything — it means nothing arrived inside the
    /// timeout, and a caller with a deadline left should ask again.
    pub fn next_frame(&mut self) -> Option<&[u8]> {
        match self.capture.next_packet() {
            Ok(packet) => Some(packet.data),
            Err(_) => None,
        }
    }
}

impl FrameSink for FrameChannel {
    fn send_frame(&mut self, frame: &[u8]) -> Result<(), String> {
        self.capture.sendpacket(frame).map_err(|e| e.to_string())
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

    /// A snapshot length below what the deepest header stack needs is raised to
    /// it.
    ///
    /// The field carries an explicit claim: it bounds what this process can see
    /// of a payload it has no business reading, and the kernel enforces that
    /// rather than userspace promising it. A zero handed to `libpcap` is a value
    /// its own manual page does not define, so the claim rested on a number the
    /// library was free to reinterpret.
    #[test]
    fn a_snapshot_length_too_short_to_read_a_reply_is_raised_to_one_that_can() {
        for asked in [0, 1, MIN_SNAP_LEN - 1] {
            let options = CaptureOptions::for_replies("tcp").with_snaplen(asked);
            assert_eq!(
                options.snaplen, MIN_SNAP_LEN,
                "a snapshot length of {asked} reached libpcap"
            );
        }

        // A length the caller meant is the length they get, in both directions
        // from the floor.
        for asked in [MIN_SNAP_LEN, MIN_SNAP_LEN + 1, REPLY_SNAP_LEN] {
            assert_eq!(
                CaptureOptions::for_replies("tcp")
                    .with_snaplen(asked)
                    .snaplen,
                asked
            );
        }
    }

    /// A guard over fabricated counters, standing in for one whose capture
    /// threads would need an interface and root to exist.
    fn guard_over(stats: Vec<Arc<CaptureStats>>) -> CaptureGuard {
        CaptureGuard {
            stop: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
            stats,
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

    /// A transport captures on every interface that is up, so the drop count a
    /// scanner acts on has to be the whole receive path's rather than one
    /// interface's - a reply lost on the one interface the probe went out of is
    /// lost whatever the others managed.
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
    /// The test the counting one below could not be: setting the flag happens
    /// inside a loop that needs a live capture, so the decision is a function
    /// and this is what holds it. A version that counted every `Err` would
    /// report a savefile read to its end as a lost interface; one that counted
    /// none would put the count back where it was, which is nowhere.
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

    /// A capture that stopped is counted, and counted in captures rather than
    /// frames, so a scan across several interfaces says how many went deaf.
    ///
    /// This was a log line and nothing else. The counters are what a report
    /// carries, and a capture that ended is the most total form of the loss they
    /// exist to make visible: an interface that hears nothing more, whose
    /// silence a scanner cannot tell from hosts that did not answer. A run could
    /// report a healthy receive path with one of eight links dead since the
    /// first second.
    #[test]
    fn a_capture_that_stopped_early_is_counted_as_one() {
        let lasted = stats_of(100, 0, 0);
        let stopped = stats_of(4, 0, 0);
        stopped.stopped_early.store(true, Ordering::Relaxed);

        assert_eq!(lasted.snapshot().stopped_early, 0);
        assert_eq!(stopped.snapshot().stopped_early, 1);

        // Summed across the guard's captures, so the number is how many links
        // were lost rather than whether any were.
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

    /// The distinction the `Option` exists for: no capture is not a capture
    /// that lost nothing.
    #[test]
    fn a_guard_over_no_capture_reports_nothing_rather_than_zero() {
        assert_eq!(CaptureGuard::noop().counts(), None);
        assert_eq!(guard_over(Vec::new()).counts(), None);
    }

    /// `pcap_stats` is cumulative from the start of the capture, so a refresh
    /// replaces the previous reading. Accumulating instead would count every
    /// dropped frame once per refresh and report a loss the network never had.
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
}
