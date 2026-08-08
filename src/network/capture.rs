// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

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
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, JoinHandle};

use pcap::{Active, Capture, Device};
use pnet::packet::ip::IpNextHeaderProtocol;
#[cfg(not(windows))]
use std::os::unix::io::AsRawFd;
use tokio::sync::mpsc;

use crate::network::frame::{self, LinkType};
use crate::{error, info, warn};

/// Largest capture we ever need: a scan reply is a bare TCP/UDP segment, but
/// snapping generously costs nothing and avoids ever truncating one.
const SNAP_LEN: i32 = 65_535;

/// How long a reader thread waits for a frame before looping back to check the
/// stop flag. Bounds shutdown latency without busy-looping.
///
/// On Unix this is the timeout of the [`wait_readable`] poll rather than
/// `libpcap`'s own read timeout, which cannot be relied on: see [`open`].
const READ_TIMEOUT_MS: i32 = 100;

/// One reply lifted off the wire: the Layer-4 segment, who sent it, and which
/// protocol it is.
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
}

/// The parsed receive stream produced by a running capture: [`CapturedSegment`]s
/// from every captured interface, interleaved in arrival order.
pub type CaptureStream = mpsc::UnboundedReceiver<CapturedSegment>;

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
    /// A guard owning no capture threads, for tests that supply a synthetic
    /// receive stream instead of a live capture.
    #[cfg(test)]
    pub fn noop() -> Self {
        Self {
            stop: Arc::new(AtomicBool::new(true)),
            handles: Vec::new(),
        }
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
pub fn start(interfaces: &[String], filter: &str) -> anyhow::Result<(CaptureStream, CaptureGuard)> {
    let (tx, rx) = mpsc::unbounded_channel();
    let stop = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::new();

    for name in interfaces {
        match open(name, filter) {
            Ok((capture, link)) => {
                info!(
                    verbosity = 1,
                    "Capturing on {name} (link type {link:?}) with filter: {filter}"
                );
                let tx = tx.clone();
                let stop = stop.clone();
                handles.push(
                    thread::Builder::new()
                        .name(format!("capture-{name}"))
                        .spawn(move || reader_loop(capture, link, tx, stop))
                        .expect("spawning capture thread"),
                );
            }
            Err(e) => warn!("Skipping capture on {name}: {e}"),
        }
    }

    if handles.is_empty() {
        anyhow::bail!("no interface could be captured for replies");
    }

    Ok((rx, CaptureGuard { stop, handles }))
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
fn reader_loop(
    mut capture: Capture<Active>,
    link: LinkType,
    tx: mpsc::UnboundedSender<CapturedSegment>,
    stop: Arc<AtomicBool>,
) {
    #[cfg(not(windows))]
    let fd = capture.as_raw_fd();

    while !stop.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some(parsed) = frame::parse_captured_segment(link, packet.data)
                    && tx
                        .send(CapturedSegment {
                            source: parsed.source,
                            protocol: parsed.protocol,
                            bytes: parsed.payload.to_vec(),
                        })
                        .is_err()
                {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => {
                #[cfg(not(windows))]
                wait_readable(fd);
            }
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                error!("Capture read error: {e}");
                break;
            }
        }
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
