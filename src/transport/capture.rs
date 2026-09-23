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
//! On BSD-derived systems, macOS included, the kernel does not deliver TCP or UDP
//! segments to raw IP sockets, those protocols being reserved to the in-kernel
//! stack, so the Layer-4 raw socket that works on Linux
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
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pcap::{Active, Capture};
use pnet_packet::ip::IpNextHeaderProtocol;
#[cfg(not(windows))]
use std::os::unix::io::AsRawFd;
use tokio::sync::mpsc;

use crate::logging::error;
use crate::model::capture::{CaptureCounts, IpObservation};
use crate::model::ip::scoped::Zone;
use crate::protocols::ethernet::VLAN_TAG_LEN;
use crate::protocols::sizes::{ETH_HDR_LEN, IP_V6_HDR_LEN};
use crate::transport::frame::{self, LinkType};
use crate::{counted, info, warn};
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
/// silence as a network that said nothing. Every other link header this crate
/// strips is shorter than the tagged Ethernet one.
///
/// It is a floor and not a default. [`CaptureOptions::with_snaplen`] raises
/// anything lower to it, which is also what keeps a zero from reaching
/// `libpcap`, whose treatment of one is undefined by its own manual page.
pub const MIN_SNAP_LEN: u32 =
    (ETH_HDR_LEN + 2 * VLAN_TAG_LEN + IP_V6_HDR_LEN + TCP_MAX_HDR_LEN) as u32;

/// A TCP header with the full forty bytes of options its data offset can
/// describe.
const TCP_MAX_HDR_LEN: usize = 60;

// The floor's argument, held at compile time because every side of it is a
// constant: a test could only restate what the compiler already knows, and a
// build is where a wrong one should stop.
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
/// Fixing two of these and leaving the third unchosen, a constant for the
/// snapshot length, `libpcap`'s own default for the buffer, and promiscuity
/// wherever the library happens to leave it, is defensible only while one
/// caller exists with one set of needs.
///
/// It stops being defensible with a second, because the settings are not
/// independent. A wide filter with a generous snapshot length and a default
/// buffer is a capture that discards most of what it admits, and the three have
/// to be decided together or not at all.
///
/// The snapshot length is also the only place a limit on what this process reads
/// of other people's traffic can be enforced by the kernel rather than by
/// discipline, which is a property worth having a type to hang on.
#[must_use]
#[derive(Debug, Clone)]
pub struct CaptureOptions {
    /// What the kernel admits, compiled for each link to a BPF program. Only
    /// matching frames are copied into this process.
    filter: CaptureFilter,
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
    /// A capture of what was addressed to this host: the replies to probes it
    /// sent.
    ///
    /// Not promiscuous, which is the difference from
    /// [`for_link_traffic`](Self::for_link_traffic). A reply to a probe this host
    /// sent comes back to this host, so accepting frames addressed elsewhere adds
    /// only other people's traffic, filling the buffer this scan's own answers
    /// have to fit in.
    ///
    /// The whole frame is kept ([`REPLY_SNAP_LEN`]). A reply is small and
    /// the filter is narrow, so snapping generously costs almost nothing where
    /// truncating one would cost an observation.
    ///
    /// The kernel's default buffer. These arrivals are bounded by the probes this
    /// host sent, so there is a rate above which nothing comes, and the default
    /// has been sufficient for it.
    pub fn for_replies(filter: impl Into<CaptureFilter>) -> Self {
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
    /// Promiscuous, which is what separates this from
    /// [`for_replies`](Self::for_replies), and not a preference. Several
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
    pub fn for_link_traffic(filter: impl Into<CaptureFilter>) -> Self {
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
    /// this process can see of a payload it has no business reading, the second
    /// being a limit the kernel enforces rather than one userspace promises to
    /// keep.
    ///
    /// Raised to [`MIN_SNAP_LEN`] where it is lower, since below that a capture
    /// cannot see the headers it exists to read and every frame arrives as a
    /// truncation. `libpcap` does not define what a snapshot length of zero
    /// means, the manual page does not say, and it has not meant the same thing
    /// across versions, so a setting whose whole argument is that the kernel
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

/// What a capture admits, in `libpcap`'s filter syntax, the syntax `tcpdump`
/// takes.
///
/// Two shapes, because a filter is compiled once per link and links differ in
/// what they can express. An [`expression`](Self::expression) is compiled as
/// written, and a link that cannot compile it is not captured on. A set of
/// alternatives, [`any_of`](Self::any_of), admits a frame any one of them
/// admits, and each link compiles the ones it can express and leaves the rest
/// out.
///
/// # Why leaving a clause out is sound, and when it is not allowed
///
/// A clause a link cannot express is one naming something the link does not
/// carry. `ether dst` names a hardware address, and a tunnel, a PPP link or a
/// loopback without an Ethernet header has none, so `libpcap` refuses to
/// compile it there: no frame on that link could have matched it. Leaving it
/// out loses nothing that link could have delivered, while refusing the whole
/// filter loses everything the other clauses would have admitted, which on a
/// tunnel is every IP packet it carries.
///
/// That argument holds for a clause the link cannot express, and not for one
/// nothing can: a clause with a typo in it is a mistake, and dropping it
/// silently would hide one. So a clause a link refuses is compiled once more
/// for Ethernet, the link that expresses the most, and only where that
/// succeeds is it left out. Otherwise the capture fails with
/// [`CaptureError::Filter`] naming it.
///
/// Alternatives suit a capture reading several unrelated kinds of traffic, as a
/// listener does. A scan's reply filter is an expression, since every part of it
/// is needed for the scan to hear its answers, and a link that can express only
/// some of it should be refused and said to be rather than captured on in part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureFilter {
    shape: FilterShape,
}

/// The two shapes a [`CaptureFilter`] takes, kept private so that a filter is
/// built through the constructors that say which one is meant.
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
    /// Each clause is a complete expression, joined to the others by `or`, so
    /// it must parenthesise anything that would not survive that.
    pub fn any_of<I, S>(clauses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            shape: FilterShape::AnyOf(clauses.into_iter().map(Into::into).collect()),
        }
    }

    /// The expression to compile on the link `capture` is open on, with the
    /// clauses left out of it to express it there.
    ///
    /// Asks `libpcap`, through the capture itself, rather than deciding from
    /// the link type here: which clauses a data-link type can express is
    /// `libpcap`'s knowledge, and a table of it kept in this crate would be a
    /// second copy of that knowledge, and wrong the first time the two
    /// disagreed.
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
                            source: malformed,
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
                source,
            }),
            _ => Ok((kept.join(" or "), left_out)),
        }
    }
}

/// Whether `clause` compiles for Ethernet, the link expressing the most, and
/// what `libpcap` said where it does not.
///
/// A handle opened dead, with no device behind it: compiling needs a link type
/// and nothing else, so this asks nothing of the host and no privilege.
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
    /// The address the segment came from.
    pub source: IpAddr,
    /// The address it was going to, so a capture admitting both directions can
    /// tell a scan's own probe from the answer to it. `None` for a synthetic
    /// stream with no IP header, as [`observation`](Self::observation) is.
    pub destination: Option<IpAddr>,
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
    /// supply one; the point is that it has to say so.
    pub observation: Option<IpObservation>,

    /// The hardware address the frame carrying this segment came from, where the
    /// link had one.
    ///
    /// Carried because it is the only thing here that can say whether a reply
    /// came from the host it claims to. Anything answering in a host's place uses
    /// that host's IP address, so [`source`](Self::source) cannot tell a genuine
    /// answer from an intercepted one; this can, on an on-link segment.
    ///
    /// Not a vendor lookup. An off-link reply carries the last-hop router's
    /// address and looks no different from here. See
    /// [`frame::source_mac`] for the full argument.
    ///
    /// `None` on a tunnel, PPP, loopback or raw-IP link, which carry no hardware
    /// address, and on a synthetic stream. Never "the sender had none".
    pub source_mac: Option<MacAddr>,

    /// When the capture thread took delivery of this segment.
    ///
    /// The earliest monotonic point in the pipeline, taken in the `libpcap`
    /// callback before the segment is queued. A round trip measured against the
    /// moment a reader dequeued it instead would carry the channel's depth and
    /// the runtime's scheduling, which on a fast link is most of what it
    /// reports: 4.5 ms of pipeline over a 0.1 ms path.
    ///
    /// Monotonic rather than the kernel's own wall-clock frame timestamp, which
    /// [`CapturedFrame::observed_at`] carries for the readers that place a
    /// finding on a timeline. A duration wants a clock that cannot be adjusted
    /// underneath it.
    pub received_at: Instant,
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
            destination: None,
            protocol,
            bytes,
            observation: None,
            received_at: Instant::now(),
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
    /// Possibly truncated, to whatever [`CaptureOptions::with_snaplen`] the
    /// capture was opened with. That is how a capture is stopped from reading
    /// more of somebody's traffic than it has any business
    /// reading, and it means a reader treats a short frame as ordinary rather
    /// than as corrupt. Every parser in [`crate::protocols`] already
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
/// Dropping blocks, for one read timeout, and the flag is what bounds it. A
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

        // A reader that panicked has already marked its capture and said so, as
        // it unwound; see `spawn_reader`. What is left here is only the wait.
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

    /// A guard over one capture that has already stopped early, with no thread
    /// behind it.
    #[cfg(test)]
    pub(crate) fn stopped_early() -> Self {
        let counters = CaptureStats::default();
        counters.stopped_early.store(true, Ordering::Relaxed);
        Self {
            stop: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
            stats: vec![Arc::new(counters)],
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
/// An interface that cannot be captured is skipped and logged rather than
/// failing the scan: a host has several, most of them irrelevant to any given
/// probe, and refusing to scan because a virtual bridge declined would be
/// wrong. Only every interface failing leaves the scan with nowhere to hear an
/// answer, and that is [`NoInterface`](Self::NoInterface), which carries each
/// link's own refusal.
///
/// Privilege is one cause among several and is said only where it is the one.
/// A root process can be refused a capture by a filter the link cannot
/// express, a framing nothing here parses, or an adapter the capture driver
/// will not bind, and a message blaming privilege for those sends somebody who
/// already holds it looking in the one place the fault is not.
/// [`is_denied`](Self::is_denied) is the question to ask.
///
/// `#[non_exhaustive]` because the capture layer is where new platform-specific
/// failures show up first.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum CaptureError {
    /// No link could be captured on, so nothing could be heard.
    ///
    /// Carries every link's refusal rather than one verdict for all of them,
    /// because they need not agree and the reason is what there is to act on.
    /// Where every one was [`Denied`](Self::Denied) the message says so in one
    /// sentence, which is the ordinary case of a process without the privilege
    /// to capture; otherwise it names each link and what refused it.
    #[error(
        "no link could be captured on, so nothing could be heard: {}",
        refusals_reason(refused)
    )]
    NoInterface {
        /// Each link tried, by name, and why it could not be captured on, in the
        /// order the links were tried.
        refused: Vec<(String, CaptureError)>,
    },
    /// Every link opened and not one of them could be given a reader thread.
    ///
    /// A runtime condition rather than a mistake: a process near its thread
    /// limit, or a cgroup that caps them. Separate from
    /// [`NoInterface`](Self::NoInterface) because the remedy is different and
    /// naming privileges here would send a reader looking in the wrong place.
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
    /// Either a mistake in the expression or a link that cannot express it: an
    /// Ethernet address means nothing on a tunnel, and `libpcap` refuses to
    /// compile one for it. The expression is named because in both cases it is
    /// the thing to look at.
    #[error("the filter `{filter}` would not compile: {}", library_message(.source))]
    Filter {
        /// The expression that was rejected.
        filter: String,
        /// What `libpcap` said.
        #[source]
        source: pcap::Error,
    },

    /// One named link could not be opened, for a reason other than privilege.
    /// Unlike `NoInterface` this names the link, because a caller asked for
    /// that one in particular and there is nothing else to fall back to.
    #[error("{interface} could not be opened: {}", library_message(.source))]
    Open {
        /// The link that refused.
        interface: String,
        /// What `libpcap` said.
        #[source]
        source: pcap::Error,
    },

    /// One named link could not be opened because this process may not
    /// capture on it.
    ///
    /// Separate from [`Open`](Self::Open) because it is the one refusal whose
    /// remedy lies outside the link: root, or wherever the platform grants the
    /// right to capture short of it, such as membership of `access_bpf` on
    /// macOS or `cap_net_raw` on Linux. It is decided by the status `libpcap`
    /// activated the handle with, never by reading its message.
    #[error(
        "{interface} could not be opened without privileges this process lacks: {}",
        library_message(.source)
    )]
    Denied {
        /// The link that refused.
        interface: String,
        /// What `libpcap` said.
        #[source]
        source: pcap::Error,
    },
}

impl CaptureError {
    /// Whether this failure is a missing privilege, and nothing else.
    ///
    /// True of a link that [`Denied`](Self::Denied) this process, and of a
    /// capture with no link because every link did. A capture refused on other
    /// grounds, even alongside some links that denied it, answers false:
    /// acquiring the privilege would not have made it work.
    pub fn is_denied(&self) -> bool {
        match self {
            Self::Denied { .. } => true,
            Self::NoInterface { refused } => {
                !refused.is_empty() && refused.iter().all(|(_, error)| error.is_denied())
            }
            _ => false,
        }
    }

    /// What went wrong, without naming the link it went wrong on, for a line
    /// that names the link its own way.
    ///
    /// A capture of one link that no link would take is that link's own
    /// refusal, so it too is told without the name. Of several, each keeps its
    /// name, since the line naming one link cannot name them all.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::NoInterface { refused } => match refused.as_slice() {
                [(_, only)] => only.reason(),
                several => refusals_reason(several),
            },
            Self::Open { source, .. } => library_message(source).into_owned(),
            Self::Denied { source, .. } => format!(
                "this process lacks the privileges to capture on it: {}",
                library_message(source)
            ),
            Self::UnsupportedLinkType { dlt, .. } => {
                format!("it carries data-link type {dlt}, which nothing here parses")
            }
            other => other.to_string(),
        }
    }
}

/// Why no link could be captured on, from each link's refusal.
///
/// One sentence where every link was denied, which is what an unprivileged
/// process meets on every link it tries and where a list of them all would say
/// the same thing once per interface. Otherwise each link by name with its own
/// reason, because then they can differ, and the one that matters may be any of
/// them.
fn refusals_reason(refused: &[(String, CaptureError)]) -> String {
    if refused.is_empty() {
        return "there was no link to capture on".to_owned();
    }
    if refused.iter().all(|(_, error)| error.is_denied()) {
        return "this process may not capture (opening a capture needs root)".to_owned();
    }

    refused
        .iter()
        .map(|(link, error)| format!("{link}: {}", error.reason()))
        .collect::<Vec<_>>()
        .join("; ")
}

/// What the capture library said, in its own words.
///
/// The `pcap` crate prefixes every message the library returns with `libpcap
/// error:`, whatever the library is. On Windows it is Npcap, and the prefix
/// reads as a library missing when one is installed and has said precisely what
/// it refused, so the message is quoted bare.
fn library_message(error: &pcap::Error) -> std::borrow::Cow<'_, str> {
    match error {
        pcap::Error::PcapError(message) => message.into(),
        other => other.to_string().into(),
    }
}

/// Opens a filtered capture on each named link and starts reading, parsing
/// every admitted frame down to the Layer-4 segment a scanner reads.
///
/// Frames that are not IP are dropped here, since the segment is what a scanner
/// reads and there is none behind an ARP frame. A caller that wants those is
/// asking a different question and wants the whole frame; see
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
                destination: Some(parsed.destination),
                protocol: parsed.protocol,
                bytes: parsed.payload.to_vec(),
                observation: Some(parsed.observation),
                source_mac,
                received_at: Instant::now(),
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
/// that fills, `libpcap` counts what it discards, so the loss lands in
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
/// [`frames`]. Everything else, meaning which failures are survivable and how
/// threads are named and stopped and when counters refresh, is identical and
/// lives
/// here so that it cannot come to differ.
///
/// Interfaces that fail to open, or whose data-link type this crate cannot
/// parse, are skipped rather than aborting the whole capture, and told about by
/// [`tell_unheard`]: a host
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

    // Named here and counted, in one line beside the per-interface ones. A scan
    // opens a capture on every interface that is up, twenty-six on an ordinary
    // laptop with a VPN and a hypervisor, and does it once per transport, so
    // both belong with the engine's working at verbosity 3, where somebody
    // asking whether it captured at all, and on which links with which filter,
    // finds them.
    let mut opened = 0usize;
    // Why the last reader thread refused to start, for the case where none did.
    let mut unstarted: Option<std::io::Error> = None;
    // The links that would not open, told about together once it is known
    // whether any did. See `tell_unheard`.
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
            Err(e) => unheard.push((zone, e)),
        }
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

    Ok(CaptureGuard {
        stop,
        handles,
        stats,
    })
}

/// Says which links could not be captured on, and why: once per link for the
/// life of the process, and on the default console only where the scan's
/// answers depend on it and no error will say so.
///
/// Every transport opens its own capture on every link, so a link that refuses
/// one refuses them all, three or four times a scan, and a front end that runs
/// several scans asks again each time. What refused is a fact about this
/// machine rather than about any one of those opens: an adapter Npcap is not
/// bound to, such as a hypervisor's or a VPN's, stays that way. So it is said
/// the first time and not again, unless it later matters more than it did.
///
/// How much it matters is [`loudness`]'s question. The link is named as a
/// person knows it, with the system's name beside it on the quiet line, where
/// somebody matching it against the capture library's own device list will be
/// reading.
fn tell_unheard(unheard: &[(&Zone, CaptureError)], every_link_failed: bool) {
    let links = crate::system::interface::interfaces();
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
    /// At verbosity 1, with the decisions behind a result: a link nothing
    /// in the scan was shown to need.
    Quiet,
    /// On the default console, because the scan's answers depend on it.
    Aloud,
}

/// How loudly a link that could not be captured on is told about.
///
/// Aloud when the scan's answers depend on it and nothing else will say so.
/// They depend on a link carrying the default route, since every target beyond
/// this machine's own segments is reached through it and answers through it,
/// and while other links were captured on the scan goes on without it, so this
/// line is the only place its loss is told. Where no link could be captured on
/// at all the capture fails, and its error names every link and what refused
/// it: the lines here go quiet rather than say each cause a second time, beside
/// the error that is already saying it. Otherwise the link is one of the
/// adapters a host keeps beside the one it uses, a hypervisor's switch, a VPN's
/// tunnel, a bridge, and a target only reaches it by sitting on its own
/// segment: quiet, where a reader asking what went uncovered will find it.
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

    /// Whether `link` is to be told about at `loudness`: never told about, or
    /// told about more quietly than it now deserves. Records it either way.
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

/// Starts the thread that reads one capture, marking the capture stopped early
/// if that thread dies.
///
/// **A reader that panicked is a link that went deaf, and the record has to say
/// so while the scan can still read it.** The thread is the only thing reading
/// its interface, so every reply that would have arrived on it becomes silence a
/// scanner cannot tell from a host that did not answer, and a log line is not
/// the record: [`reader_loop`] sets the same flag when pcap ends the link, for
/// the same reason. The mark is made in the unwind, by the dying thread, because
/// every scanner reads its capture counts with the guard still alive. Set when
/// the guard joined its threads, it would be set after the only read.
///
/// Every reader goes through here, so no path starts one without the mark.
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
/// Npcap lists an adapter as `\Device\NPF_` followed by the GUID Windows
/// names it by, and that full form is the one its device list hands out and
/// its open call is documented against. A name already in that form, or one
/// that is not a GUID at all, such as Npcap's own loopback adapter, is passed
/// through unchanged.
#[cfg_attr(not(windows), allow(dead_code))]
fn npcap_device_name(name: &str) -> String {
    if name.starts_with('{') {
        format!("\\Device\\NPF_{name}")
    } else {
        name.to_owned()
    }
}

/// A capture [`open`] brought up, with what it is and what `libpcap` had to say
/// about bringing it up.
struct Opened {
    capture: Capture<Active>,
    /// How its frames are framed.
    link: LinkType,
    /// The warning `libpcap` activated it under, if it gave one. See
    /// [`libpcap`].
    warning: Option<String>,
    /// The clauses of its filter this link could not express, and so does not
    /// admit. See [`CaptureFilter`].
    left_out: Vec<String>,
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
fn open(name: &str, options: &CaptureOptions) -> Result<Opened, CaptureError> {
    let (capture, warning) = libpcap::activate(
        name,
        &libpcap::Setup {
            snaplen: saturating_i32(options.snaplen),
            promiscuous: options.promiscuous,
            timeout_ms: READ_TIMEOUT_MS,
            immediate: true,
            // Left alone unless asked for, so that not choosing a buffer size
            // keeps whatever the platform's `libpcap` decided rather than this
            // crate picking a number for every capture on every operating
            // system it runs on.
            buffer_bytes: options.buffer_bytes.map(saturating_i32),
        },
    )?;

    #[cfg(not(windows))]
    let capture = capture.setnonblock().map_err(|source| CaptureError::Open {
        interface: name.to_owned(),
        source,
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
        .map_err(|source| CaptureError::Filter { filter, source })?;

    Ok(Opened {
        capture,
        link,
        warning,
        left_out,
    })
}

/// Narrows a byte count to the signed width `libpcap` takes, saturating rather
/// than wrapping.
///
/// Both settings this converts are sizes, and both are meaningless as negative
/// numbers: a wrapped snapshot length is a capture that keeps nothing, which
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
/// `deliver` is given the whole `libpcap` packet, its bytes and the header
/// carrying the kernel's timestamp, and says whether to carry on. Both outputs
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

/// Waits for `fd` to have a frame ready, giving up after `timeout_ms` so the
/// caller can re-check its stop flag or its deadline. Poll failures are not
/// reported: the caller's next read reports anything genuinely wrong, and an
/// interrupted poll simply costs one extra loop.
#[cfg(not(windows))]
fn wait_readable(fd: std::os::unix::io::RawFd, timeout_ms: i32) {
    let mut poll_fd = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };

    // SAFETY: `poll_fd` is a single initialized `pollfd` and the count says so;
    // `poll` reads it and writes only `revents`.
    unsafe { libc::poll(&mut poll_fd, 1, timeout_ms) };
}

/// A handle for putting whole frames on a link.
///
/// The send half of the same library the receive half already uses. Sending
/// through another library would put two open on one interface for one scan:
/// a `pnet` channel, say, whose receiver is discarded beside the `pcap`
/// capture that reads, and a discarded receiver is a kernel buffer nothing
/// drains.
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
    /// capture with no filter at all would fill a kernel buffer nobody reads,
    /// the defect a discarded receiver has. `less 0` asks for frames shorter
    /// than nothing.
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
/// the stream, with no interface and no privileges involved.
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
/// same handle mutably, which is why this is one type rather than a pair, and why
/// it is not what [`frames`] gives a scanner, whose reader lives on its own thread
/// and cannot share a borrow with anybody.
///
/// The filter is the caller's, for the reason it always is here: what a frame is
/// worth is decided by whoever reads it.
pub struct FrameChannel {
    capture: Capture<Active>,
    /// How long [`next_frame`](Self::next_frame) waits for a frame to arrive.
    /// Windows has no descriptor to wait on, and its capture's own read
    /// timeout does the waiting there.
    #[cfg(not(windows))]
    wait_ms: i32,
    /// The frame [`next_frame`](Self::next_frame) last read, copied out of
    /// `libpcap`'s buffer so that reading it and waiting for it can be
    /// separate steps. See [`next_frame`](Self::next_frame).
    frame: Vec<u8>,
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

        // Non-blocking, with the wait done on the descriptor, for the reason
        // `open` gives: on Linux a blocking read waits until a frame arrives
        // whatever the read timeout says. See `next_frame`.
        #[cfg(not(windows))]
        let capture = capture.setnonblock().map_err(|source| CaptureError::Open {
            interface: link.to_owned(),
            source,
        })?;

        let mut capture = capture;
        capture
            .filter(filter, true)
            .map_err(|source| CaptureError::Filter {
                filter: filter.to_owned(),
                source,
            })?;

        Ok(Self {
            capture,
            #[cfg(not(windows))]
            wait_ms,
            frame: Vec::new(),
        })
    }

    /// The next frame the filter admitted, or `None` if none arrived within
    /// the read timeout.
    ///
    /// `None` is not the end of anything. It means nothing arrived inside the
    /// timeout, and a caller with a deadline left should ask again.
    ///
    /// # How the wait is bounded
    ///
    /// On Unix the read never blocks. A frame already waiting is returned at
    /// once; otherwise the wait is a `poll` on the capture's descriptor, bounded
    /// by the read timeout, followed by one more read. That is the discipline
    /// every reader thread in this module keeps, and for the same reason:
    /// `libpcap`'s own read timeout does not bound a blocking read on Linux, and
    /// a caller relying on it, such as an address resolution waiting on a
    /// neighbour that will never answer, would wait until some unrelated frame
    /// happens to pass the filter, which on a quiet link is never.
    ///
    /// The read comes before the wait rather than after it because `libpcap`
    /// may already hold frames it read from the kernel in one batch, which a
    /// descriptor that has nothing more to give would not announce. Windows
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

/// Bringing a capture handle up, the one step taken through `libpcap` itself
/// rather than through the `pcap` crate.
///
/// # Why this step, and only this one
///
/// `pcap_activate` has three kinds of answer, not two. Zero is success and a
/// negative status is failure. A positive status is a *warning*: the handle is
/// live and capturing, and `libpcap` wants it known that it is not quite what
/// was asked for. `PCAP_WARNING_PROMISC_NOTSUP` is a link that will not go
/// promiscuous. `PCAP_WARNING` is, among other things, how Linux brings up a
/// link whose hardware type `libpcap` has no mapping for, a GRE tunnel or an
/// `ip6tnl` or `ip6gre` link, which it serves cooked as `DLT_LINUX_SLL` and
/// [`LinkType::LinuxSll`] reads.
///
/// The `pcap` crate's `Capture::open` treats every non-zero status as failure
/// and closes the handle, warnings included. Through it, a GRE tunnel cannot be
/// captured on at all, and neither can any link that merely declined to be
/// promiscuous, so a scan through one hears nothing and reads its targets as
/// down.
///
/// The crate leaves no way round that. A handle becomes an active capture only
/// through that call, and it cannot be moved out of the crate's inactive type
/// into its active one without closing it or leaking the wrapper that owns it.
/// So the handle is created and activated here and adopted into a
/// `Capture<Active>` the moment it exists, through the conversion the crate
/// provides for a raw handle. From then on it is the crate's: every read,
/// filter, statistic and send goes through its API, and so does the close.
///
/// The alternatives were worse. Forking the crate to change one comparison is
/// a dependency this tree would have to carry. Capturing on Linux's `any`
/// device and filtering by interface index would serve only Linux, and would
/// copy every link's traffic into the kernel filter to find one link's. The
/// seam here is eight functions `libpcap` has exported unchanged since 1.5,
/// every one of which the crate declares too, so linking it asks nothing of
/// `libpcap` or Npcap that the crate did not already.
mod libpcap {
    use std::ffi::{CStr, CString, c_char, c_int};
    use std::marker::{PhantomData, PhantomPinned};
    use std::ptr::NonNull;

    use pcap::{Active, Capture};

    use super::{CaptureError, device_name};

    /// `libpcap`'s capture handle, which this side only ever holds a pointer
    /// to.
    ///
    /// Declared here rather than named from the `pcap` crate, which keeps its
    /// bindings private. The pointer is converted to the crate's own type once,
    /// in [`activate`], and the two name the same C struct.
    #[repr(C)]
    struct Handle {
        _opaque: [u8; 0],
        _unmovable: PhantomData<(*mut u8, PhantomPinned)>,
    }

    /// The size `libpcap` requires of the buffer `pcap_create` writes an error
    /// into, `PCAP_ERRBUF_SIZE`.
    const ERRBUF_SIZE: usize = 256;

    // `pcap_activate`'s statuses, from `pcap/pcap.h`. Every negative status is a
    // failure and every positive one a warning; these are the ones this module
    // has words of its own for, where `libpcap` left its error buffer empty.
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
    /// Together because `libpcap` accepts every one of them only on a handle
    /// not yet activated, and the crate's builders for them are on the type
    /// this module does not use.
    pub(super) struct Setup {
        pub(super) snaplen: c_int,
        pub(super) promiscuous: bool,
        pub(super) timeout_ms: c_int,
        pub(super) immediate: bool,
        /// `None` leaves `libpcap`'s own default in place.
        pub(super) buffer_bytes: Option<c_int>,
    }

    /// Creates a capture handle on `link`, sets it up, and activates it,
    /// returning it with the warning it was activated under, if any.
    ///
    /// A warning is not a failure. The handle is live, and the warning says in
    /// what way it differs from what was asked for; the caller decides whether
    /// that is worth saying.
    pub(super) fn activate(
        link: &str,
        setup: &Setup,
    ) -> Result<(Capture<Active>, Option<String>), CaptureError> {
        let device = CString::new(device_name(link)).map_err(|_| CaptureError::Open {
            interface: link.to_owned(),
            source: pcap::Error::InvalidInputString,
        })?;

        let mut errbuf = [0 as c_char; ERRBUF_SIZE];
        // SAFETY: `device` is a NUL-terminated string that outlives the call,
        // and `errbuf` is the `PCAP_ERRBUF_SIZE` bytes `pcap_create` may write.
        let created = unsafe { pcap_create(device.as_ptr(), errbuf.as_mut_ptr()) };
        let Some(created) = NonNull::new(created) else {
            // SAFETY: on failure `pcap_create` has written a NUL-terminated
            // message into `errbuf`, which was zeroed, so it is terminated
            // either way.
            let message = unsafe { CStr::from_ptr(errbuf.as_ptr()) };
            return Err(CaptureError::Open {
                interface: link.to_owned(),
                source: pcap::Error::PcapError(message.to_string_lossy().into_owned()),
            });
        };

        // Adopted before it is activated, so that every path out of this
        // function, the failures below included, closes it through the
        // crate's own `Drop`, which is what `libpcap` asks of a handle whose
        // activation failed. Nothing but the pointer is read from it until
        // activation has succeeded.
        let capture: Capture<Active> = Capture::from(created.cast());
        let handle = capture.as_ptr().cast::<Handle>();

        // SAFETY: `handle` is the live handle `pcap_create` returned, owned by
        // `capture` for the rest of this function, and not yet activated,
        // which is the only state in which these calls are defined. Each
        // returns an error only for an activated handle.
        unsafe {
            pcap_set_snaplen(handle, setup.snaplen);
            pcap_set_promisc(handle, c_int::from(setup.promiscuous));
            pcap_set_timeout(handle, setup.timeout_ms);
            pcap_set_immediate_mode(handle, c_int::from(setup.immediate));
            if let Some(bytes) = setup.buffer_bytes {
                pcap_set_buffer_size(handle, bytes);
            }
        }

        // SAFETY: as above; activation is the call these settings were for.
        let status = unsafe { pcap_activate(handle) };
        let message = || status_message(handle, status);

        match status {
            0 => Ok((capture, None)),
            warning if warning > 0 => Ok((capture, Some(message()))),
            failure => Err(refusal(link, failure, message())),
        }
    }

    /// The error a handle that failed to activate with `status` is reported
    /// as.
    ///
    /// Privilege is read from the status and from nothing else. `libpcap`
    /// reports a missing privilege as its own status, on every platform, while
    /// its words for it differ between them and between releases, and a check
    /// that matched the words would come to blame privilege for a failure it
    /// did not cause, or miss the one it did.
    pub(super) fn refusal(link: &str, status: c_int, message: String) -> CaptureError {
        let source = pcap::Error::PcapError(message);
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

    /// What `libpcap` said about `status`, in its own words where it wrote
    /// some.
    ///
    /// `pcap_geterr` holds the detail for most statuses and is empty for a
    /// few, where the status alone is the whole of what is known. Those are
    /// named here in the words `pcap_statustostr` would use, rather than
    /// through that function, which is the one this module would declare that
    /// the crate does not.
    fn status_message(handle: *mut Handle, status: c_int) -> String {
        // SAFETY: `handle` is live, and `pcap_geterr` returns a pointer into
        // it, NUL-terminated, valid until the next call on the handle. It is
        // copied out before anything else is.
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

    /// An adapter that refuses is named once, and the capture library's own
    /// words say why. The `pcap` crate prefixes every message with `libpcap
    /// error:`, which on Windows reads as a missing library when Npcap is
    /// installed and has said exactly what is wrong.
    #[test]
    fn a_refused_open_names_the_adapter_once_and_quotes_the_library() {
        let guid = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
        let message = "Error opening adapter: Network interface was not found.";
        let refused = CaptureError::Open {
            interface: guid.to_owned(),
            source: pcap::Error::PcapError(message.to_owned()),
        };

        assert_eq!(
            refused.to_string(),
            format!("{guid} could not be opened: {message}")
        );
        assert_eq!(refused.reason(), message, "the reason leaves the name out");
    }

    /// A link refused for want of privilege is said to be, and one refused for
    /// anything else is not.
    ///
    /// The status decides it, which is the property: `libpcap` reports a
    /// missing privilege as a status of its own, and a message blaming
    /// privilege for a failure it did not cause sends somebody who holds it
    /// looking in the one place the fault is not.
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

    /// A capture no link would take names each link and its reason, and
    /// blames privilege in one sentence only where privilege refused them all.
    #[test]
    fn a_capture_no_link_would_take_says_why_each_refused() {
        let denied = |link: &str| CaptureError::Denied {
            interface: link.to_owned(),
            source: pcap::Error::PcapError("Operation not permitted".into()),
        };
        let filter = CaptureError::Filter {
            filter: "ether dst 02:00:00:00:00:01".into(),
            source: pcap::Error::PcapError(
                "ethernet addresses supported only on ethernet/FDDI/token ring".into(),
            ),
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

    /// And through the real opening path: a link that does not exist is
    /// refused, and the error blames privilege exactly when the refusal was
    /// one.
    ///
    /// Which refusal a machine gives depends on it. An unprivileged Linux
    /// process is denied before the device is ever looked up, and a macOS user
    /// in `access_bpf` or a root process is told there is no such device. The
    /// property holds in both, and the link is named wherever privilege is not
    /// the whole of the answer.
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

    /// Of a set of alternatives, a link keeps the ones it can express and
    /// leaves out the ones it cannot, and says which it left out.
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

    /// A clause nothing can express is a mistake, and is refused rather than
    /// left out.
    ///
    /// Leaving a clause out is sound only because the link could not have
    /// carried what it matches. A typo matches nothing anywhere, and dropping
    /// it silently would turn a mistake in the filter into traffic that is
    /// never seen, on every link, with nothing said.
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

    /// A link that can express none of the alternatives is refused, naming the
    /// filter whole.
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

    /// An expression is compiled whole, never narrowed. A scan's reply filter
    /// is one, since every part of it is needed to hear the answers, and a link
    /// that can express only some of it is refused rather than captured on in
    /// part.
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

    /// A frame channel bounds its own wait, on the descriptor, rather than
    /// trusting `libpcap`'s read timeout to end a blocking read.
    ///
    /// Linux does not end one on the timeout: its memory-mapped path polls
    /// again, and the read returns only when a frame passes the filter. An
    /// address resolution waiting there on a neighbour that will never answer
    /// waits for as long as the link stays quiet. So the capture must not be a
    /// blocking one, which is the property this holds; that the wait then ends
    /// on a quiet Linux link is Tier 3's to show.
    ///
    /// Needs the right to capture on the loopback, and says nothing where the
    /// process lacks it.
    #[test]
    fn a_frame_channel_bounds_its_wait_itself_rather_than_trusting_libpcap() {
        let Some(loopback) = crate::system::interface::interfaces()
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

    /// A link the scan's answers depend on goes to the default console, and
    /// one they do not goes where a reader asking what went uncovered looks.
    /// A host keeps hypervisor, VPN and bridge adapters beside the one it
    /// uses, and a default console telling of each on every scan is noise
    /// about links no target was reached through.
    ///
    /// Where no link was heard at all the capture's error names every link and
    /// its cause, so the lines here would only repeat it.
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

    /// Every transport a scan opens asks every link again, so a link that
    /// refused is told about once, and again only if it comes to matter more.
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

    /// Npcap opens an adapter by its own name, the Windows GUID under the
    /// driver's prefix. Handed the bare GUID an interface list gives, the
    /// capture every raw strategy stands on would fail to open.
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

    /// The stamp is taken where the segment is taken, so a round trip measured
    /// against it carries the path and not the queue behind it.
    #[test]
    fn a_segment_is_stamped_before_it_is_queued() {
        use std::net::Ipv4Addr;

        use pnet_packet::ip::IpNextHeaderProtocols;

        let before = Instant::now();
        let segment = CapturedSegment::synthetic(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpNextHeaderProtocols::Tcp,
            vec![0; 20],
        );
        let after = Instant::now();

        assert!(segment.received_at >= before && segment.received_at <= after);
    }
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
    /// A log line is not enough. The counters are what a report carries, and a
    /// capture that ended is the most total form of the loss they exist to make
    /// visible: an interface that hears nothing more, whose silence a scanner
    /// cannot tell from hosts that did not answer. Logged and not counted, a run
    /// could report a healthy receive path with one of eight links dead since
    /// the first second.
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

    /// The flag is read while the guard is alive, which is when every scanner
    /// reads it: the counts go into the scan's own report before the transport
    /// is dropped. So a reader that panics has to say so before the guard joins
    /// it, and the counters here are the guard's own, with no clone held outside
    /// it to read them through.
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

    /// And a reader that ended cleanly is not reported as having stopped early,
    /// or the count means nothing.
    #[test]
    fn a_capture_thread_that_finished_is_not_recorded_as_stopping_early() {
        let counters = Arc::new(CaptureStats::default());
        let guard = CaptureGuard {
            stop: Arc::new(AtomicBool::new(false)),
            handles: vec![
                spawn_reader("test0", Arc::clone(&counters), |_| {}).expect("a thread starts"),
            ],
            stats: vec![Arc::clone(&counters)],
        };

        drop(guard);
        assert!(!counters.stopped_early.load(Ordering::Relaxed));
    }
}
