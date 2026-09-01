// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Sending and hearing whole frames on one segment
//!
//! What a local sweep holds: somewhere to put Ethernet frames, and the frames
//! that arrived on the same link.
//!
//! ## The two halves come from different places, and should
//!
//! The send half is a `pnet` link-layer channel, because emitting a frame this
//! crate built byte for byte is what it is for. The receive half is a
//! [`capture`], because everything that makes a
//! receive path trustworthy lives there: a BPF filter the *kernel* applies, the
//! counters saying what the kernel discarded anyway, and a stop flag every
//! reader thread checks so that dropping the handle ends them.
//!
//! It was one channel doing both until this was split. That channel copied every
//! frame on the segment into this process to throw nearly all of them away, could
//! not say what it had lost, and its reader thread had no way to be told to stop.
//! All three are properties of the receive side alone, and all three were already
//! solved one module over.

use crate::system::interface::Link;

use crate::model::capture::CaptureCounts;
use crate::transport::capture::{self, CaptureGuard, CaptureOptions, FrameSink, FrameStream};

/// How many frames may wait for the consumer at once.
///
/// A sweep reads its queue inside the same loop that paces its probes, so a tick
/// spent sending is a tick not spent receiving, and the queue is what covers
/// that gap. Sized for a burst, since every host on a `/24` answering an ARP
/// sweep at once is a few hundred frames, rather than for a sustained rate, which
/// the caller's filter is what keeps small.
const QUEUE_DEPTH: usize = 1024;

/// A live Ethernet channel: somewhere to put frames, and a stream of the frames
/// that arrived.
///
/// This is the link-layer counterpart to
/// [`ProbeTransport`](crate::transport::probe::ProbeTransport), and deliberately
/// not the same type. A probe transport carries Layer-4 segments with the link
/// and IP headers already stripped, which is all the SYN and UDP scanners need.
/// Local discovery needs the whole frame: it identifies a neighbour by the
/// Ethernet source MAC, and reads ARP, which has no Layer-4 segment to strip to.
pub struct EthernetHandle {
    /// Where a frame goes to reach the wire, link header included.
    pub tx: Box<dyn FrameSink>,
    /// The frames the capture admitted, in arrival order, each possibly
    /// truncated to the snaplen the capture was opened with.
    pub rx: FrameStream,
    /// Keeps the capture thread alive for this handle's lifetime, and holds the
    /// counters it publishes.
    capture: CaptureGuard,
}

impl EthernetHandle {
    /// What the receive path's kernel buffer has done so far.
    ///
    /// A sweep reports this alongside its own counters because the two answer
    /// different halves of one question. The sweep knows how many replies it
    /// saw; only this knows how many arrived and were discarded before it could.
    /// A frame lost here is indistinguishable from a host that never answered,
    /// which makes it the one loss a sweep has to be told about rather than left
    /// to infer.
    ///
    /// `None` for a handle with no capture behind it, so a synthetic frame
    /// stream never reports a clean receive path it never had.
    pub fn capture_counts(&self) -> Option<CaptureCounts> {
        self.capture.counts()
    }

    /// Builds a handle over a caller-supplied sender and frame stream, opening
    /// no channel and starting no capture.
    ///
    /// The link-layer twin of
    /// [`ProbeTransport::from_parts`](crate::transport::probe::ProbeTransport::from_parts):
    /// `tx` observes the frames a scanner emits, and whatever is pushed onto the
    /// sending half of `rx` arrives as though it had been captured off the
    /// interface. That is what lets ARP and NDP discovery be tested without an
    /// interface or the privileges to open one.
    ///
    /// Requires the `test-support` feature outside this crate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_parts(tx: Box<dyn FrameSink>, rx: FrameStream) -> Self {
        Self {
            tx,
            rx,
            capture: CaptureGuard::noop(),
        }
    }
}

/// Why a link-layer channel could not be opened.
///
/// The variants name the interface, because a scan opens one channel per segment
/// it means to sweep and "opening a channel failed" is not actionable without
/// knowing which.
/// Two halves open here and either can refuse, so which one did is the whole of
/// what this says. Both usually fail for the same underlying reason, that sending
/// and receiving raw frames needs root everywhere this engine runs, and a person
/// reading the message needs to know whether their probes would have
/// left, not only that something went wrong.
///
/// There were three variants and one of them was ever constructed. `NoCapture`
/// carried both failures, including the send half's, while its own
/// documentation said the send half had already opened; `Open` and
/// `NotEthernet` were named, documented and unreachable.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// The link would not open for sending, so no probe could leave by it.
    #[error("{interface} would not open for sending, so no probe could leave by it: {source}")]
    Send {
        /// The interface that refused.
        interface: String,
        /// What the capture layer said.
        #[source]
        source: capture::CaptureError,
    },

    /// The send half opened but nothing could be captured on the interface, so
    /// probes would leave and no answer could ever be heard.
    ///
    /// Separate from [`Send`](Self::Send) because it fails at a different point
    /// and costs something different: the link is already carrying this scan's
    /// frames by the time this happens.
    #[error("nothing could be captured on {interface}, so no reply could be heard: {source}")]
    Receive {
        /// The interface in question.
        interface: String,
        /// What the capture layer said.
        #[source]
        source: capture::CaptureError,
    },
}

/// Opens both halves on one interface: a link-layer sender, and a capture of the
/// frames that link carries which `filter` admits.
///
/// The capture is promiscuous and `filter` is what narrows it, two halves of one
/// decision, argued at
/// [`CaptureOptions::for_link_traffic`](crate::transport::capture::CaptureOptions::for_link_traffic).
///
/// The filter belongs to the caller, since what a frame is worth is decided by
/// whoever reads it. This module knows how to open a capture and
/// nothing about ARP, neighbour discovery or DHCP; a filter written here would
/// be a scanner's knowledge kept one layer below the scanner, and would go stale
/// the first time a reader was added without anybody thinking to look down here.
pub fn start_capture(link: &Link, filter: &str) -> Result<EthernetHandle, ChannelError> {
    // Two handles on the one library, rather than one handle each on two. See
    // `FrameSender`: this used to open a `pnet` channel for the sending half and
    // discard its receiver, leaving a kernel buffer nothing drained.
    let tx = capture::FrameSender::open(link.name()).map_err(|source| ChannelError::Send {
        interface: link.name().to_owned(),
        source,
    })?;

    let zone = link.zone();
    let (rx, capture) = capture::frames(
        std::slice::from_ref(&zone),
        &CaptureOptions::for_link_traffic(filter),
        QUEUE_DEPTH,
    )
    .map_err(|source| ChannelError::Receive {
        interface: link.name().to_owned(),
        source,
    })?;

    Ok(EthernetHandle {
        tx: Box::new(tx),
        rx,
        capture,
    })
}
