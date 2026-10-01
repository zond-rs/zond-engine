// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Sending and hearing whole frames on one segment
//!
//! What a local sweep holds: somewhere to put Ethernet frames, and the frames that
//! arrived on the same link.
//!
//! ## Two handles on one library
//!
//! The send half is a [`capture::FrameSender`], a `libpcap` handle that puts a frame
//! this crate built byte for byte on the wire. The receive half is a [`capture`],
//! which brings a BPF filter the kernel applies, counters for what the kernel
//! discarded anyway, and a stop flag every reader thread checks so that dropping the
//! handle ends them.
//!
//! Two handles, because a reader thread parked waiting for frames cannot share a
//! borrow with the sender. One library, because a second one opened on the link to
//! send would bring a receiver of its own, and a receiver nobody reads is a kernel
//! buffer nobody drains.

use crate::system::interface::Link;

use crate::model::capture::CaptureCounts;
use crate::transport::capture::{self, CaptureGuard, CaptureOptions, FrameSink, FrameStream};

/// How many frames may wait for the consumer at once.
///
/// A sweep reads its queue inside the loop that paces its probes, so the queue covers
/// the ticks spent sending. Sized for a burst: every host on a `/24` answering an ARP
/// sweep at once is a few hundred frames. The caller's filter keeps the sustained rate
/// small.
const QUEUE_DEPTH: usize = 1024;

/// A live Ethernet channel: somewhere to put frames, and a stream of the frames that
/// arrived.
///
/// The link-layer counterpart to
/// [`ProbeTransport`](crate::transport::probe::ProbeTransport), which carries Layer-4
/// segments with the link and IP headers stripped. Local discovery needs the whole
/// frame: it identifies a neighbour by the Ethernet source MAC, and reads ARP, which
/// has no Layer-4 segment.
#[non_exhaustive]
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
    /// A sweep knows how many replies it saw; only this knows how many arrived and
    /// were discarded before it could read them. A frame lost here looks exactly like
    /// a host that never answered, so a sweep reports these counts with its own.
    ///
    /// `None` for a handle with no capture behind it.
    pub fn capture_counts(&self) -> Option<CaptureCounts> {
        self.capture.counts()
    }

    /// Builds a handle over a caller-supplied sender and frame stream, opening no
    /// channel and starting no capture.
    ///
    /// The link-layer twin of
    /// [`ProbeTransport::from_parts`](crate::transport::probe::ProbeTransport::from_parts):
    /// `tx` observes the frames a scanner emits, and whatever is pushed onto the
    /// sending half of `rx` arrives as though captured off the interface. Lets ARP and
    /// NDP discovery be tested without an interface or privileges.
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
/// Each variant names the interface once; the capture layer's error, kept as the
/// source, contributes only its reason to the message.
///
/// Says which half refused. Both usually fail for the same reason, that raw frames
/// need root everywhere this engine runs, but the reader needs to know whether
/// probes would have left.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// The link would not open for sending, so no probe could leave by it.
    #[error(
        "{interface} would not open for sending, so no probe could leave by it: {}",
        source.reason()
    )]
    Send {
        /// The interface that refused.
        interface: String,
        /// What the capture layer said.
        #[source]
        source: capture::CaptureError,
    },

    /// The send half opened but nothing could be captured on the interface, so
    /// probes would leave and no answer could be heard.
    ///
    /// By the time this happens the link may already be carrying this scan's frames.
    #[error(
        "nothing could be captured on {interface}, so no reply could be heard: {}",
        source.reason()
    )]
    Receive {
        /// The interface in question.
        interface: String,
        /// What the capture layer said.
        #[source]
        source: capture::CaptureError,
    },
}

/// Opens both halves on one interface: a link-layer sender, and a capture of the
/// frames on that link which `filter` admits.
///
/// The capture is promiscuous and `filter` narrows it; see
/// [`CaptureOptions::for_link_traffic`](crate::transport::capture::CaptureOptions::for_link_traffic).
///
/// The filter is the caller's, since the reader decides what a frame is worth. This
/// module knows nothing about ARP, neighbour discovery or DHCP.
pub fn start_capture(link: &Link, filter: &str) -> Result<EthernetHandle, ChannelError> {
    // One library, two handles. See `FrameSender`: a `pnet` channel opened to send
    // would bring a receiver nothing drains.
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
    use crate::transport::capture::{CaptureError, LibraryError};

    /// How often `needle` appears in `haystack`.
    fn occurrences(haystack: &str, needle: &str) -> usize {
        haystack.matches(needle).count()
    }

    /// A channel that could not hear names its link once, and says why.
    ///
    /// The capture layer's error also names the link; quoting it whole would print
    /// the name twice around a second statement of the same failure.
    #[test]
    fn a_channel_that_could_not_hear_names_its_link_once() {
        let refused = ChannelError::Receive {
            interface: "en0".into(),
            source: CaptureError::NoInterface {
                refused: vec![(
                    "en0".into(),
                    CaptureError::Open {
                        interface: "en0".into(),
                        source: LibraryError::new(pcap::Error::PcapError(
                            "BIOCSETIF failed".into(),
                        )),
                    },
                )],
            },
        };

        assert_eq!(
            refused.to_string(),
            "nothing could be captured on en0, so no reply could be heard: BIOCSETIF failed"
        );
    }

    /// And one that could not send, on the same rule.
    #[test]
    fn a_channel_that_could_not_send_names_its_link_once() {
        let refused = ChannelError::Send {
            interface: "en0".into(),
            source: CaptureError::Denied {
                interface: "en0".into(),
                source: LibraryError::new(pcap::Error::PcapError(
                    "/dev/bpf0: Permission denied".into(),
                )),
            },
        };
        let said = refused.to_string();

        assert_eq!(occurrences(&said, "en0"), 1, "{said}");
        assert!(said.contains("Permission denied"), "{said}");
    }
}
