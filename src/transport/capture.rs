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
use pnet::packet::ip::IpNextHeaderProtocol;
#[cfg(not(windows))]
use std::os::unix::io::AsRawFd;
use tokio::sync::mpsc;

use crate::model::capture::{CaptureCounts, IpObservation};
use crate::model::ip::scoped::Zone;
use crate::transport::frame::{self, LinkType};
use crate::{error, info, warn};
use pnet::util::MacAddr;

/// Largest capture a scan's receive path ever needs: a reply is a bare TCP/UDP
/// segment, but snapping generously costs nothing against a filter this narrow
/// and avoids ever truncating one.
const REPLY_SNAP_LEN: u32 = 65_535;

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
    pub fn with_snaplen(mut self, bytes: u32) -> Self {
        self.snaplen = bytes;
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
pub type CaptureStream = mpsc::UnboundedReceiver<CapturedSegment>;

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
        }
    }
}

/// Keeps a set of live per-interface captures running for as long as it's
/// held. Dropping it signals every reader thread to stop; each exits at its
/// next read timeout, so no capture thread outlives the guard.
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
        for handle in self.handles.drain(..) {
            let _ = handle.join();
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
}

/// Opens a filtered capture on each named link and starts reading, parsing
/// every admitted frame down to the Layer-4 segment a scanner reads.
///
/// **Frames that are not IP are dropped here**, because the segment is what a
/// scanner reads and there is none behind an ARP frame. A caller that wants
/// those is asking a different question and wants the whole frame — see
/// [`frames`], which this is otherwise the twin of.
///
/// # The stream is unbounded, and may be
///
/// What arrives here is bounded by what this host sent: a reply exists because a
/// probe was emitted, and the scanner emitting them is the same task reading
/// this. There is no rate at which the network can fill this faster than the
/// scan chooses to. [`frames`] has no such guarantee and is bounded for it.
pub fn segments(
    links: &[Zone],
    options: &CaptureOptions,
) -> Result<(CaptureStream, CaptureGuard), CaptureError> {
    let (tx, rx) = mpsc::unbounded_channel();

    let guard = spawn_captures(links, options, move |_zone, link| {
        let tx = tx.clone();
        move |packet: &pcap::Packet<'_>| {
            let Some(parsed) = frame::parse_captured_segment(link, packet.data) else {
                return ControlFlow::Continue(());
            };

            let sent = tx.send(CapturedSegment {
                source: parsed.source,
                protocol: parsed.protocol,
                bytes: parsed.payload.to_vec(),
                observation: Some(parsed.observation),
                source_mac: frame::source_mac(link, packet.data),
            });

            if sent.is_err() {
                ControlFlow::Break(())
            } else {
                ControlFlow::Continue(())
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

    let guard = spawn_captures(links, options, move |zone, link| {
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
    mut deliver_for: impl FnMut(&Zone, LinkType) -> D,
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

    for zone in links {
        let name = zone.name();
        match open(name, options) {
            Ok((capture, link)) => {
                info!(verbosity = 3, "capturing on {name} (link type {link:?})");
                opened += 1;

                let deliver = deliver_for(zone, link);
                let stop = stop.clone();
                let counters = Arc::new(CaptureStats::default());
                stats.push(counters.clone());
                let name = name.to_owned();

                handles.push(
                    thread::Builder::new()
                        .name(format!("capture-{name}"))
                        .spawn(move || reader_loop(capture, &stop, &name, &counters, deliver))
                        .expect("spawning capture thread"),
                );
            }
            Err(e) => warn!("skipping capture on {name}: {e}"),
        }
    }

    if handles.is_empty() {
        return Err(CaptureError::NoInterface);
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
fn open(name: &str, options: &CaptureOptions) -> anyhow::Result<(Capture<Active>, LinkType)> {
    let device = Device::from(name);
    let mut inactive = Capture::from_device(device)?
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

    let capture = inactive.open()?;

    #[cfg(not(windows))]
    let capture = capture.setnonblock()?;

    let mut capture = capture;
    let link = LinkType::from_dlt(capture.get_datalink().0);
    if let LinkType::Unsupported(dlt) = link {
        anyhow::bail!("unsupported data-link type {dlt}");
    }

    capture
        .filter(&options.filter, true)
        .map_err(|e| anyhow::anyhow!("compiling BPF filter `{}`: {e}", options.filter))?;

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
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                error!("capture read error: {e}");
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
            })
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
            }
        );
    }
}
