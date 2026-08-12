// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// use crate::adapters::outbound::terminal::print;
use pnet::datalink;
use pnet::datalink::{Channel, Config, DataLinkReceiver, DataLinkSender, NetworkInterface};
use std::thread;
use std::time::Duration;
use tokio::sync::mpsc;

const READ_TIMEOUT_MS: u64 = 50;

/// A live Ethernet channel: somewhere to put frames, and a stream of the frames
/// that arrived.
///
/// This is the link-layer counterpart to
/// [`ProbeTransport`](crate::network::probe::ProbeTransport), and deliberately
/// not the same type. A probe transport carries Layer-4 segments with the link
/// and IP headers already stripped, which is all the SYN and UDP scanners need.
/// Local discovery needs the whole frame: it identifies a neighbour by the
/// Ethernet source MAC, which a capture would have thrown away long before the
/// segment reached it.
pub struct EthernetHandle {
    pub tx: Box<dyn DataLinkSender>,
    pub rx: mpsc::UnboundedReceiver<Vec<u8>>,
}

impl EthernetHandle {
    /// Builds a handle over a caller-supplied sender and frame stream, opening
    /// no channel and starting no listener thread.
    ///
    /// The link-layer twin of
    /// [`ProbeTransport::from_parts`](crate::network::probe::ProbeTransport::from_parts):
    /// `tx` observes the frames a scanner emits, and whatever is pushed onto the
    /// sending half of `rx` arrives as though it had been captured off the
    /// interface. That is what lets ARP and NDP discovery be tested without an
    /// interface or the privileges to open one.
    ///
    /// Requires the `test-support` feature outside this crate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_parts(tx: Box<dyn DataLinkSender>, rx: mpsc::UnboundedReceiver<Vec<u8>>) -> Self {
        Self { tx, rx }
    }
}

/// Why a link-layer channel could not be opened.
///
/// Both variants name the interface, because a scan opens one channel per
/// segment it means to sweep and "opening a channel failed" is not actionable
/// without knowing which.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    /// The operating system refused the channel. Usually missing privileges:
    /// sending and receiving raw frames needs root everywhere this engine runs.
    #[error("opening a link-layer channel on {interface} failed: {source}")]
    Open {
        /// The interface that refused.
        interface: String,
        /// What the operating system said.
        #[source]
        source: std::io::Error,
    },

    /// The interface opened but is not Ethernet, so the frames this scanner
    /// builds mean nothing on it.
    #[error("{interface} is not an Ethernet interface")]
    NotEthernet {
        /// The interface in question.
        interface: String,
    },
}

pub fn start_capture(intf: &NetworkInterface) -> Result<EthernetHandle, ChannelError> {
    let cfg = Config {
        read_timeout: Some(Duration::from_millis(READ_TIMEOUT_MS)),
        ..Default::default()
    };
    let (tx, rx_socket) = open_eth_channel(intf, datalink::channel, cfg)?;
    let (queue_tx, queue_rx) = mpsc::unbounded_channel();
    spawn_eth_listener(queue_tx, rx_socket);
    Ok(EthernetHandle { tx, rx: queue_rx })
}

/// The two halves of an open link-layer channel: somewhere to put frames, and
/// the frames arriving.
pub type EthernetChannel = (Box<dyn DataLinkSender>, Box<dyn DataLinkReceiver>);

pub fn open_eth_channel<F>(
    intf: &NetworkInterface,
    channel_opener: F,
    cfg: Config,
) -> Result<EthernetChannel, ChannelError>
where
    F: FnOnce(&NetworkInterface, Config) -> std::io::Result<datalink::Channel>,
{
    let ch: Channel = channel_opener(intf, cfg).map_err(|source| ChannelError::Open {
        interface: intf.name.clone(),
        source,
    })?;

    match ch {
        Channel::Ethernet(tx, rx) => Ok((tx, rx)),
        _ => Err(ChannelError::NotEthernet {
            interface: intf.name.clone(),
        }),
    }
}

pub fn spawn_eth_listener(
    eth_tx: mpsc::UnboundedSender<Vec<u8>>,
    eth_rx: Box<dyn DataLinkReceiver>,
) {
    thread::spawn(move || {
        let mut eth_iter = eth_rx;
        loop {
            if let Ok(frame) = eth_iter.next()
                && eth_tx.send(frame.to_vec()).is_err()
            {
                break;
            }
        }
    });
}
