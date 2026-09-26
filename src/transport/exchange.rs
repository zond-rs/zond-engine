// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Send one probe and collect what answers
//!
//! [`protocols::craft`](crate::protocols::craft) builds a segment and
//! [`ProbeTransport`] carries one, and between the two sit half a dozen
//! decisions: which source address this host would use for the destination,
//! which interface a link-local address is valid on, which filter the capture
//! has to be opened with for the reply to be seen at all, and how long to wait.
//!
//! Every one of those is a decision this crate already knows how to make, and
//! every one of them, got wrong, produces the same symptom: no reply, which
//! reads as a filtered port rather than as a mistake.
//!
//! ```no_run
//! use std::time::Duration;
//! use zond_engine::protocols::craft::{Packet, Tcp, tcp_flags};
//! use zond_engine::transport::exchange::Exchange;
//! use zond_engine::transport::probe::ProbeKind;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // The filter decides what can come back, so it is named rather than guessed.
//! let mut exchange = Exchange::open(ProbeKind::TcpProbe {
//!     reply_port: 50_000,
//!     icmp_errors: true,
//! })?;
//!
//! let probe = Packet::new().push(Tcp::new(50_000, 80).with_flags(tcp_flags::SYN));
//! let replies = exchange
//!     .send(&probe, "192.0.2.10".parse()?, Duration::from_millis(500))
//!     .await?;
//!
//! for reply in &replies {
//!     println!("{} answered {} bytes", reply.source, reply.bytes.len());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## The segment stops at Layer 4
//!
//! What goes to [`send`](Exchange::send) is a transport segment: a TCP header
//! and its payload, a UDP datagram, an ICMP message. The IP header is placed by
//! whichever backend the send mode chose, from the destination and the
//! [`Emission`], because that is the seam
//! [`ProbeSender`](crate::transport::probe::ProbeSender) draws and both
//! backends draw it in the same place. A raw socket lets the kernel stamp the
//! header; a link-layer sender builds it along with the frame.
//!
//! So a packet whose *IP header* is wrong on purpose does not go out this way.
//! Everything below that line is reachable: a TCP header claiming a data offset
//! it does not have, a UDP length that counts the wrong bytes, an ICMP message
//! of a type nothing answers. [`Field::Exact`](crate::protocols::craft::Field)
//! is how each of those is written, and none of it is checked on the way past.
//!
//! ## Which replies come back
//!
//! Whatever the capture's filter admitted, in arrival order, until `wait` runs
//! out or [`MAX_REPLIES`] have been collected.
//!
//! They are not narrowed to the address the probe went to, and that is
//! deliberate: an ICMP error comes from a router in the path rather than from
//! the destination, and it is often the only thing that answers. Narrowing by
//! source would drop the most informative reply a probe can draw. What narrows
//! the traffic is the [`ProbeKind`] the exchange was opened with, which is why
//! that stays the caller's to choose.
//!
//! [`capture_counts`](Exchange::capture_counts) says how many frames the kernel
//! discarded before this could read them, which is the difference between a
//! quiet destination and a receive path that could not keep up.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::model::capture::CaptureCounts;
use crate::protocols::craft::Packet;
use crate::protocols::error::PacketError;
use crate::system::interface::{NoSource, SourceResolver};
use crate::transport::capture::CapturedSegment;
use crate::transport::probe::{
    Emission, ProbeKind, ProbeTransport, SendError, SendMode, TransportError,
};

/// The most replies one [`send`](Exchange::send) collects.
///
/// A bound rather than a setting. The capture admits everything its filter
/// matches, which on a busy segment is other people's traffic as well as this
/// probe's answers, and a caller waiting a second for one reply should not be
/// handed a hundred thousand. A caller that wants the whole stream holds a
/// [`ProbeTransport`] and reads it directly.
pub const MAX_REPLIES: usize = 256;

/// What stopped a probe from going out, or from being built at all.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// The transport could not be opened. A missing capture, no raw socket, or
    /// no interface to send from.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// The segment could not be built from the layers it was given.
    #[error(transparent)]
    Build(#[from] PacketError),

    /// The probe was built and the host would not send it.
    #[error(transparent)]
    Send(#[from] SendError),

    /// This host has no source address for that destination.
    ///
    /// Distinct from [`SendError::Unroutable`], which is the sender reporting
    /// the same fact about its own backend. This one is found before a socket is
    /// touched, by reading the interface table.
    #[error("no source address on this host reaches {0}")]
    NoSource(IpAddr),
}

/// One probe out, and what answered.
///
/// Holds the transport, the interface table the source address is chosen from,
/// and the [`Emission`] every probe leaves under. See the module documentation
/// for where the segment it takes stops.
pub struct Exchange {
    transport: ProbeTransport,
    sources: SourceResolver,
    emission: Emission,
}

impl Exchange {
    /// Opens an exchange for `kind`, letting the platform pick the send backend.
    ///
    /// `kind` compiles the capture filter, so it decides what a reply may be. A
    /// TCP probe whose answer might be an ICMP error needs
    /// [`ProbeKind::TcpProbe`] with `icmp_errors` set, or the error is filtered
    /// out before it ever reaches this.
    ///
    /// # Errors
    ///
    /// [`ExchangeError::Transport`] when the capture or the send backend cannot
    /// be opened, which on most platforms means the process is not privileged.
    pub fn open(kind: ProbeKind) -> Result<Self, ExchangeError> {
        Self::open_with(kind, SendMode::Auto)
    }

    /// [`open`](Self::open), with the send backend named rather than chosen.
    ///
    /// [`SendMode::Ethernet`] is what an [`Emission`] setting a source hardware
    /// address or a fragment size needs; see
    /// [`Emission::requires_link_layer`].
    ///
    /// # Errors
    ///
    /// As [`open`](Self::open).
    pub fn open_with(kind: ProbeKind, mode: SendMode) -> Result<Self, ExchangeError> {
        Ok(Self {
            transport: ProbeTransport::open_with(kind, mode)?,
            sources: SourceResolver::from_system(),
            emission: Emission::routed(),
        })
    }

    /// Sets what every probe from this exchange leaves under: the hop limit, a
    /// spoofed source hardware address, a fragment size.
    ///
    /// [`EvasionProfile::emission`](crate::evasion::EvasionProfile::emission)
    /// produces one from a profile.
    #[must_use]
    pub fn with_emission(mut self, emission: Emission) -> Self {
        self.emission = emission;
        self
    }

    /// Builds `segment`, sends it to `to`, and collects replies for `wait`.
    ///
    /// The source address and the zone a link-local destination is valid on are
    /// read from this host's interface table. Returns as soon as `wait` is spent
    /// or [`MAX_REPLIES`] have arrived, and an empty vector is a destination
    /// that said nothing rather than an error.
    ///
    /// # Errors
    ///
    /// [`ExchangeError::Build`] if the layers describe a packet that cannot be
    /// serialized, [`ExchangeError::NoSource`] if no address on this host
    /// reaches `to`, and [`ExchangeError::Send`] if the probe was refused on the
    /// way out, or this process had no descriptor to ask the routing table
    /// for its source with.
    pub async fn send(
        &mut self,
        segment: &Packet,
        to: IpAddr,
        wait: Duration,
    ) -> Result<Vec<CapturedSegment>, ExchangeError> {
        let bytes = segment.build()?;
        let source = self.sources.source(to).map_err(|missing| match missing {
            NoSource::Unreached => ExchangeError::NoSource(to),
            NoSource::Unasked(error) => ExchangeError::Send(SendError::from_io(error)),
        })?;
        let zone = self.sources.zone_of(to);

        self.transport
            .tx
            .send(&bytes, source, to, zone, self.emission)?;

        Ok(self.collect(wait).await)
    }

    /// What the receive path's kernel buffers have done so far.
    ///
    /// A probe that drew nothing and a probe whose reply was dropped before it
    /// could be read look identical from [`send`](Self::send). This is what
    /// tells them apart. [`None`] for a transport with no capture behind it.
    pub fn capture_counts(&self) -> Option<CaptureCounts> {
        self.transport.capture_counts()
    }

    /// Reads the capture until `wait` is spent or the cap is reached.
    async fn collect(&mut self, wait: Duration) -> Vec<CapturedSegment> {
        let deadline = Instant::now() + wait;
        let mut replies = Vec::new();

        while replies.len() < MAX_REPLIES {
            let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                break;
            };
            match tokio::time::timeout(left, self.transport.rx.recv()).await {
                Ok(Some(segment)) => replies.push(segment),
                // The capture ended, so waiting out the rest of the deadline
                // would report a silence that nothing was listening for.
                Ok(None) => break,
                Err(_) => break,
            }
        }

        replies
    }

    /// An exchange over a supplied transport and interface table, for a test
    /// with neither a socket nor a network.
    ///
    /// The counterpart of [`ProbeTransport::from_parts`], and gated for the same
    /// reason: a synthetic transport has no use in a shipped binary.
    #[cfg(feature = "test-support")]
    pub fn from_parts(transport: ProbeTransport, sources: SourceResolver) -> Self {
        Self {
            transport,
            sources,
            emission: Emission::routed(),
        }
    }
}
