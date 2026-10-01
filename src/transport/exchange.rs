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
//! [`ProbeTransport`] carries one. [`Exchange`] makes the decisions in between: which
//! source address this host uses for the destination, which interface a link-local
//! address is valid on, which capture filter lets the reply be seen, and how long to
//! wait. Getting any of them wrong produces no reply, which looks like a silent port.
//!
//! ```no_run
//! use std::time::Duration;
//! use zond_engine::protocols::craft::{Packet, Tcp, tcp_flags};
//! use zond_engine::transport::exchange::Exchange;
//! use zond_engine::transport::probe::ProbeKind;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // The filter decides what can come back.
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
//! [`send`](Exchange::send) takes a transport segment: a TCP header and its payload, a
//! UDP datagram, an ICMP message. The backend the send mode chose places the IP header,
//! from the destination and the [`Emission`]: a raw socket lets the kernel stamp it, a
//! link-layer sender builds it with the frame. That is the seam
//! [`ProbeSender`](crate::transport::probe::ProbeSender) draws.
//!
//! So a packet with a malformed *IP header* cannot be sent this way.
//! Everything above it can: a TCP header claiming a data offset it does not have, a
//! UDP length that counts the wrong bytes, an ICMP message of a type nothing answers.
//! Write those with [`Field::Exact`](crate::protocols::craft::Field); nothing checks
//! them on the way out.
//!
//! ## Which replies come back
//!
//! Whatever the capture's filter admitted, in arrival order, until `wait` runs out or
//! [`MAX_REPLIES`] have been collected.
//!
//! Replies are not narrowed to the probe's destination address. An ICMP error comes
//! from a router in the path and is often the only answer. The [`ProbeKind`] the
//! exchange was opened with is what narrows the traffic.
//!
//! [`capture_counts`](Exchange::capture_counts) says how many frames the kernel
//! discarded before they could be read, which separates a quiet destination from a
//! receive path that could not keep up.

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
/// The capture admits everything its filter matches, which on a busy segment
/// includes other people's traffic. A caller that wants the whole stream holds a
/// [`ProbeTransport`] and reads it directly.
pub const MAX_REPLIES: usize = 256;

/// What stopped a probe from going out, or from being built at all.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ExchangeError {
    /// The transport could not be opened: no capture, no raw socket, or no
    /// interface to send from.
    #[error(transparent)]
    Transport(#[from] TransportError),

    /// The segment could not be built from the layers it was given.
    #[error(transparent)]
    Build(#[from] PacketError),

    /// The probe was built and the host refused to send it.
    #[error(transparent)]
    Send(#[from] SendError),

    /// This host has no source address for that destination.
    ///
    /// Found from the interface table before any socket is touched.
    /// [`SendError::Unroutable`] is the sender's backend reporting the same fact.
    #[error("no source address on this host reaches {0}")]
    NoSource(IpAddr),
}

/// One probe out, and what answered.
///
/// Holds the transport, the interface table the source address is chosen from, and
/// the [`Emission`] every probe is sent with.
pub struct Exchange {
    transport: ProbeTransport,
    sources: SourceResolver,
    emission: Emission,
}

impl Exchange {
    /// Opens an exchange for `kind`, letting the platform pick the send backend.
    ///
    /// `kind` compiles the capture filter, so it decides what a reply may be. A TCP
    /// probe whose answer might be an ICMP error needs [`ProbeKind::TcpProbe`] with
    /// `icmp_errors` set, or the error is filtered out.
    ///
    /// # Errors
    ///
    /// [`ExchangeError::Transport`] when the capture or the send backend cannot be
    /// opened, which on most platforms means the process is not privileged.
    pub fn open(kind: ProbeKind) -> Result<Self, ExchangeError> {
        Self::open_with(kind, SendMode::Auto)
    }

    /// [`open`](Self::open) with an explicit send backend.
    ///
    /// An [`Emission`] that sets a source hardware address or a fragment size needs
    /// [`SendMode::Ethernet`]; see [`Emission::requires_link_layer`].
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

    /// Sets what every probe from this exchange is sent with: the hop limit, a
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
    /// The source address, and the zone for a link-local destination, come from this
    /// host's interface table. Returns when `wait` is spent or [`MAX_REPLIES`] have
    /// arrived. An empty vector means the destination said nothing.
    ///
    /// # Errors
    ///
    /// [`ExchangeError::Build`] if the layers cannot be serialized,
    /// [`ExchangeError::NoSource`] if no address on this host reaches `to`, and
    /// [`ExchangeError::Send`] if the probe was refused, or no descriptor was available
    /// to query the routing table for the source, or the table gave no answer.
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
            NoSource::Unanswered(error) => ExchangeError::Send(SendError::unanswered_route(&error)),
        })?;
        let zone = self.sources.zone_of(to);

        self.transport
            .tx
            .send(&bytes, source, to, zone, self.emission)?;

        Ok(self.collect(wait).await)
    }

    /// What the receive path's kernel buffers have done so far.
    ///
    /// Tells a probe that drew nothing from one whose reply was dropped before it
    /// could be read. [`None`] for a transport with no capture behind it.
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
                // The capture ended; waiting out the deadline would report a
                // silence nothing was listening for.
                Ok(None) => break,
                Err(_) => break,
            }
        }

        replies
    }

    /// An exchange over a supplied transport and interface table, for tests with
    /// neither a socket nor a network.
    ///
    /// Gated like [`ProbeTransport::from_parts`].
    #[cfg(feature = "test-support")]
    pub fn from_parts(transport: ProbeTransport, sources: SourceResolver) -> Self {
        Self {
            transport,
            sources,
            emission: Emission::routed(),
        }
    }
}
