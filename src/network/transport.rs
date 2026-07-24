// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Raw Transport-Layer Sockets
//!
//! Wraps `pnet`'s raw transport-layer (Layer 4) sockets behind a single
//! handle that streams incoming packets over a Tokio channel, so async
//! scanning code never has to touch the underlying blocking socket API
//! directly.
//!
//! A raw socket is bound to one address family: an IPv4 socket can neither
//! send to nor receive from an IPv6 destination, and vice versa. TCP
//! scanning needs both, since targets can be either, so [`start_packet_capture`]
//! opens one socket per address family for [`TransportType::TcpLayer4`] and
//! merges their incoming traffic into a single stream. [`TransportType::UdpLayer4`]
//! stays IPv4-only, since nothing in this crate currently needs UDP over IPv6.

use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use anyhow::Context;
use pnet::{
    packet::{Packet, ip::IpNextHeaderProtocols},
    transport::{
        self, TransportChannelType, TransportProtocol, TransportReceiver, TransportSender,
    },
};
use tokio::sync::mpsc;

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

/// A handle to an open raw-socket capture: a sender for outgoing packets and
/// a channel yielding incoming ones as they arrive.
pub struct TransportHandle {
    pub tx: TransportSenderHandle,
    pub rx: mpsc::UnboundedReceiver<(Vec<u8>, IpAddr)>,
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

macro_rules! spawn_listener {
    ($tx:expr, $rx:expr, $iter_func:path) => {
        std::thread::spawn(move || {
            let mut iterator = $iter_func(&mut $rx);
            loop {
                if let Ok((packet, source_ip)) = iterator.next() {
                    if $tx.send((packet.packet().to_vec(), source_ip)).is_err() {
                        break;
                    }
                }
            }
        })
    };
}

pub fn start_packet_capture(transport_type: TransportType) -> anyhow::Result<TransportHandle> {
    let (queue_tx, queue_rx) = mpsc::unbounded_channel();

    let tx = match transport_type {
        TransportType::TcpLayer4 => {
            let (v4_tx, mut v4_rx) = open_channel(CHANNEL_TYPE_TCP_V4)?;
            let v4_queue_tx = queue_tx.clone();
            spawn_listener!(v4_queue_tx, v4_rx, pnet::transport::tcp_packet_iter);

            // IPv6 raw sockets aren't available on every host (some sandboxes
            // and containers block them even as root); TCP scanning still
            // works over IPv4 alone, so a failure here isn't fatal.
            let v6 = open_channel(CHANNEL_TYPE_TCP_V6)
                .ok()
                .map(|(v6_tx, mut v6_rx)| {
                    let v6_queue_tx = queue_tx.clone();
                    spawn_listener!(v6_queue_tx, v6_rx, pnet::transport::tcp_packet_iter);
                    Arc::new(Mutex::new(v6_tx))
                });

            TransportSenderHandle {
                v4: Some(Arc::new(Mutex::new(v4_tx))),
                v6,
            }
        }
        TransportType::UdpLayer4 => {
            let (tx, mut rx) = open_channel(CHANNEL_TYPE_UDP_V4)?;
            spawn_listener!(queue_tx, rx, pnet::transport::udp_packet_iter);
            TransportSenderHandle {
                v4: Some(Arc::new(Mutex::new(tx))),
                v6: None,
            }
        }
    };

    Ok(TransportHandle { tx, rx: queue_rx })
}

fn open_channel(
    channel_type: TransportChannelType,
) -> anyhow::Result<(TransportSender, TransportReceiver)> {
    let (tx, rx) = transport::transport_channel(TRANSPORT_BUFFER_SIZE, channel_type)?;
    Ok((tx, rx))
}
