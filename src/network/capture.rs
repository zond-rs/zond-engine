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
use tokio::sync::mpsc;

use crate::network::frame::{self, LinkType};
use crate::{error, info, warn};

/// Largest capture we ever need: a scan reply is a bare TCP/UDP segment, but
/// snapping generously costs nothing and avoids ever truncating one.
const SNAP_LEN: i32 = 65_535;

/// `libpcap` read timeout. In immediate mode this bounds how long a reader
/// thread blocks before it can observe the stop flag, so shutdown is prompt
/// without busy-looping.
const READ_TIMEOUT_MS: i32 = 100;

/// The parsed receive stream produced by a running capture: `(layer4_segment,
/// source_ip)` pairs from every captured interface, interleaved in arrival
/// order.
pub type CaptureStream = mpsc::UnboundedReceiver<(Vec<u8>, IpAddr)>;

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
fn open(name: &str, filter: &str) -> anyhow::Result<(Capture<Active>, LinkType)> {
    let device = Device::from(name);
    let mut capture = Capture::from_device(device)?
        .immediate_mode(true)
        .snaplen(SNAP_LEN)
        .timeout(READ_TIMEOUT_MS)
        .open()?;

    let link = LinkType::from_dlt(capture.get_datalink().0);
    if let LinkType::Unsupported(dlt) = link {
        anyhow::bail!("unsupported data-link type {dlt}");
    }

    capture
        .filter(filter, true)
        .map_err(|e| anyhow::anyhow!("compiling BPF filter `{filter}`: {e}"))?;

    Ok((capture, link))
}

/// Blocking read loop for one capture: parse each frame down to its Layer-4
/// segment and forward it, until the stop flag is set or the consumer hangs
/// up. Read timeouts are the normal idle case, not an error.
fn reader_loop(
    mut capture: Capture<Active>,
    link: LinkType,
    tx: mpsc::UnboundedSender<(Vec<u8>, IpAddr)>,
    stop: Arc<AtomicBool>,
) {
    while !stop.load(Ordering::Relaxed) {
        match capture.next_packet() {
            Ok(packet) => {
                if let Some((source, segment)) = frame::parse_captured_segment(link, packet.data)
                    && tx.send((segment.to_vec(), source)).is_err()
                {
                    break;
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(pcap::Error::NoMorePackets) => break,
            Err(e) => {
                error!("Capture read error: {e}");
                break;
            }
        }
    }
}
