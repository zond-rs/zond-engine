// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Raw Transport-Layer Sockets (Send Path)
//!
//! Wraps `pnet`'s raw transport-layer (Layer 4) sockets for *sending* probes,
//! so async scanning code never touches the blocking socket API directly.
//!
//! This module deliberately opens no receiver. Receiving TCP/UDP over a raw
//! socket works on Linux but is silently dead on macOS/BSD, whose kernels
//! never deliver those protocols to raw sockets - so replies are captured at
//! the link layer via [`crate::network::capture`] instead, and every scanner
//! pairs this send-only handle with that capture through
//! [`crate::network::probe::ProbeTransport`].
//!
//! A raw socket is bound to one address family: an IPv4 socket can neither
//! send to nor receive from an IPv6 destination, and vice versa. TCP scanning
//! needs both, since targets can be either, so [`open_sender`] opens one
//! socket per address family for [`TransportType::TcpLayer4`].
//! [`TransportType::UdpLayer4`] stays IPv4-only, since nothing in this crate
//! currently needs UDP over IPv6.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use pnet::{
    packet::{Packet, ip::IpNextHeaderProtocols},
    transport::{
        self, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
    },
};

const TRANSPORT_BUFFER_SIZE: usize = 4096;
const CHANNEL_TYPE_UDP_V4: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Udp));
const CHANNEL_TYPE_TCP_V4: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv4(IpNextHeaderProtocols::Tcp));
const CHANNEL_TYPE_TCP_V6: TransportChannelType =
    TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocols::Tcp));

/// Which transport-layer protocol, and address family coverage, to open a capture for.
#[derive(Debug, Clone, Copy)]
pub enum TransportType {
    /// Raw TCP segments, over both IPv4 and IPv6 where available.
    TcpLayer4,
    /// Raw UDP datagrams, over IPv4 only.
    UdpLayer4,
}

/// Routes an outgoing packet to whichever underlying raw socket matches its
/// destination's address family.
///
/// A [`TransportType::UdpLayer4`] handle only ever has an IPv4 sender, so
/// sending to an IPv6 destination through it fails with a clear error rather
/// than silently doing nothing.
pub struct TransportSenderHandle {
    v4: Option<Arc<Mutex<TransportSender>>>,
    v6: Option<Arc<Mutex<TransportSender>>>,
}

impl TransportSenderHandle {
    pub fn send_to<T: Packet>(&self, packet: T, destination: IpAddr) -> anyhow::Result<usize> {
        let sender = match destination {
            IpAddr::V4(_) => self.v4.as_ref(),
            IpAddr::V6(_) => self.v6.as_ref(),
        }
        .with_context(|| format!("no open transport socket for {destination}'s address family"))?;

        sender
            .lock()
            .unwrap()
            .send_to(packet, destination)
            .with_context(|| format!("failed to send to {destination}"))
    }
}

/// Opens only the outgoing half of a raw transport capture: the raw
/// socket(s) needed to *send* segments, with no receiver threads.
///
/// Sending over a raw Layer-4 socket works on every supported OS - it's only
/// *receiving* TCP/UDP this way that BSD-derived kernels refuse - so the
/// [`RawIpSender`](crate::network::probe::RawIpSender) pairs this send-only
/// handle with a `libpcap` capture for replies instead of the (silently dead
/// on macOS) raw-socket receiver.
pub fn open_sender(transport_type: TransportType) -> anyhow::Result<TransportSenderHandle> {
    match transport_type {
        TransportType::TcpLayer4 => {
            let (v4_tx, _v4_rx) = open_channel(CHANNEL_TYPE_TCP_V4)?;
            // IPv6 raw sockets aren't available on every host; TCP scanning
            // still works over IPv4 alone, so a failure here isn't fatal.
            let v6 = open_channel(CHANNEL_TYPE_TCP_V6)
                .ok()
                .map(|(v6_tx, _v6_rx)| Arc::new(Mutex::new(v6_tx)));
            Ok(TransportSenderHandle {
                v4: Some(Arc::new(Mutex::new(v4_tx))),
                v6,
            })
        }
        TransportType::UdpLayer4 => {
            let (v4_tx, _v4_rx) = open_channel(CHANNEL_TYPE_UDP_V4)?;
            Ok(TransportSenderHandle {
                v4: Some(Arc::new(Mutex::new(v4_tx))),
                v6: None,
            })
        }
    }
}

fn open_channel(
    channel_type: TransportChannelType,
) -> anyhow::Result<(TransportSender, TransportReceiver)> {
    let (tx, rx) = transport::transport_channel(TRANSPORT_BUFFER_SIZE, channel_type)?;
    Ok((tx, rx))
}
