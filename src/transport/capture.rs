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

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, JoinHandle};

use pcap::{Active, Capture, Device};
use pnet::packet::ip::IpNextHeaderProtocol;
#[cfg(not(windows))]
use std::os::unix::io::AsRawFd;
use tokio::sync::mpsc;

use crate::model::capture::{CaptureCounts, IpObservation};
use crate::transport::frame::{self, LinkType};
use crate::{error, info, warn};
use pnet::util::MacAddr;

/// Largest capture we ever need: a scan reply is a bare TCP/UDP segment, but
/// snapping generously costs nothing and avoids ever truncating one.
const SNAP_LEN: i32 = 65_535;

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

/// Opens a filtered capture on each named interface and starts reading.
///
/// `filter` is a `libpcap` filter expression (`tcpdump` syntax) compiled into
/// a kernel BPF program; only matching frames reach userspace. Interfaces
/// that fail to open, or whose data-link type this crate can't parse, are
/// logged and skipped rather than aborting the whole capture - a scan across
/// several interfaces shouldn't die because one of them is unusual.
///
/// Fails only if *no* interface could be captured, since a transport with no
/// receive path is useless.
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

pub fn start(
    interfaces: &[String],
    filter: &str,
) -> Result<(CaptureStream, CaptureGuard), CaptureError> {
    let (tx, rx) = mpsc::unbounded_channel();
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
    let mut opened: Vec<&str> = Vec::new();

    for name in interfaces {
        match open(name, filter) {
            Ok((capture, link)) => {
                info!(verbosity = 3, "Capturing on {name} (link type {link:?})");
                opened.push(name.as_str());
                let tx = tx.clone();
                let stop = stop.clone();
                let counters = Arc::new(CaptureStats::default());
                stats.push(counters.clone());
                let name = name.clone();
                handles.push(
                    thread::Builder::new()
                        .name(format!("capture-{name}"))
                        .spawn(move || reader_loop(capture, link, tx, stop, &name, &counters))
                        .expect("spawning capture thread"),
                );
            }
            Err(e) => warn!("Skipping capture on {name}: {e}"),
        }
    }

    if handles.is_empty() {
        return Err(CaptureError::NoInterface);
    }

    info!(
        verbosity = 1,
        "Capturing on {} interface(s) with filter: {filter}",
        opened.len()
    );

    Ok((
        rx,
        CaptureGuard {
            stop,
            handles,
            stats,
        },
    ))
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
fn open(name: &str, filter: &str) -> anyhow::Result<(Capture<Active>, LinkType)> {
    let device = Device::from(name);
    let capture = Capture::from_device(device)?
        .immediate_mode(true)
        .snaplen(SNAP_LEN)
        .timeout(READ_TIMEOUT_MS)
        .open()?;

    #[cfg(not(windows))]
    let capture = capture.setnonblock()?;

    let mut capture = capture;
    let link = LinkType::from_dlt(capture.get_datalink().0);
    if let LinkType::Unsupported(dlt) = link {
        anyhow::bail!("unsupported data-link type {dlt}");
    }

    capture
        .filter(filter, true)
        .map_err(|e| anyhow::anyhow!("compiling BPF filter `{filter}`: {e}"))?;

    Ok((capture, link))
}

/// Read loop for one capture: parse each frame down to its Layer-4 segment and
/// forward it, until the stop flag is set or the consumer hangs up. Having no
/// frame ready is the normal idle case, not an error.
///
/// The loop also keeps `counters` current, since what this thread fails to read
/// in time is invisible everywhere else: a frame the kernel discards for want of
/// buffer space never reaches the channel, so no downstream counter can miss it.
fn reader_loop(
    mut capture: Capture<Active>,
    link: LinkType,
    tx: mpsc::UnboundedSender<CapturedSegment>,
    stop: Arc<AtomicBool>,
    name: &str,
    counters: &CaptureStats,
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
                if let Some(parsed) = frame::parse_captured_segment(link, packet.data)
                    && tx
                        .send(CapturedSegment {
                            source: parsed.source,
                            protocol: parsed.protocol,
                            bytes: parsed.payload.to_vec(),
                            observation: Some(parsed.observation),
                            source_mac: frame::source_mac(link, packet.data),
                        })
                        .is_err()
                {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {}
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                error!("Capture read error: {e}");
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
            "Capture on {name} lost frames: {} dropped, {} dropped by the interface, of {} received",
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
