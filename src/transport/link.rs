// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Layer-2 (Ethernet) Send Backend
//!
//! A [`ProbeSender`] that builds and emits complete Ethernet frames itself. Two cases
//! need it:
//!
//! - **Windows**, which blocks raw-socket TCP sends, so a SYN probe has to be written
//!   at the link layer.
//! - **Host-stack bypass**: a frame crafted end to end, source MAC included, skips the
//!   local firewall and connection tracking that a raw-socket send still passes
//!   through.
//!
//! [`NeighborResolver`] decides, per packet, which interface to send from and the
//! next-hop MAC: the interface holding the packet's source address, the gateway the OS
//! names for off-link targets, and an ARP resolution for on-link ones, run
//! concurrently with every other resolution the sender has in flight. A packet whose
//! source only a tunnel holds has no Ethernet route and is refused, so it is never
//! framed onto the physical link the tunnel was meant to bypass.
//!
//! On-link IPv6 returns an error because NDP neighbour solicitation is not
//! implemented. Off-link IPv6 works, since the gateway's MAC comes from the OS.

mod resolution;

pub(crate) use resolution::ARP_TIMEOUT;
#[cfg(test)]
pub(crate) use resolution::tests::{Answers, Segment};

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use crate::model::mac::MacAddr;

use crate::transport::capture::{self, FrameSink};
use crate::transport::frame;
use crate::transport::kernel_neighbors::NeighborState;
use crate::transport::neighbor::{LinkRoute, NeighborResolver};
use crate::transport::probe::{Emission, IpProtocols, ProbeSender, SendError};

use resolution::{Ask, Resolutions};

/// A Layer-2 send backend. Each interface's send handle is opened on first use and
/// reused.
pub struct EthernetSender {
    /// Shared with the [`LinkNeighbors`] a scan reads, which routes a destination to
    /// its next hop the same way a send does.
    resolver: Arc<Mutex<NeighborResolver>>,
    /// The address resolutions this sender runs, shared with the same
    /// [`LinkNeighbors`].
    resolutions: Arc<Resolutions>,
    /// A send-only handle per interface. The resolutions read ARP on their own
    /// channels, so nothing reads these, and a filter that admits nothing keeps
    /// their buffers empty.
    channels: Mutex<HashMap<String, capture::FrameSender>>,
    /// The IP protocol number to stamp into the headers this sender builds, one per
    /// address family. Fixed per sender because a transport carries one kind of
    /// probe; see [`EthernetSender::from_system`].
    protocols: IpProtocols,
    /// The loopback interface, where this sender reaches it; see
    /// [`loopback_link`].
    loopback: Option<String>,
}

impl EthernetSender {
    /// Builds a sender over the system's Ethernet-capable interfaces, emitting
    /// segments as `protocols` says for the family being addressed.
    ///
    /// This sender writes the IP header itself and the segment is opaque bytes, so it
    /// must be told the protocol. The protocols are fixed here because a transport is
    /// opened for one `ProbeKind`. They are a pair because a kind carrying ICMP uses a
    /// different protocol number per family. A wrong number is invisible locally: the
    /// datagram reaches the wrong protocol handler and is never answered.
    ///
    /// Returns `None` if the host has no Ethernet-capable interface (only tunnels or
    /// loopback), so the caller can fall back to the raw-IP path.
    pub fn from_system(protocols: IpProtocols) -> Option<Self> {
        let resolver = NeighborResolver::from_system();
        if !resolver.has_ethernet() {
            return None;
        }
        Some(Self {
            resolver: Arc::new(Mutex::new(resolver)),
            resolutions: Arc::new(Resolutions::from_system()),
            channels: Mutex::new(HashMap::new()),
            protocols,
            loopback: loopback_link(),
        })
    }

    /// Where this sender's resolution of each destination's next hop stands, for a
    /// scan that holds its probes while a resolution runs.
    pub(crate) fn neighbors(&self) -> LinkNeighbors {
        LinkNeighbors {
            resolver: Arc::clone(&self.resolver),
            resolutions: Arc::clone(&self.resolutions),
        }
    }

    /// Determines the next-hop MAC for `route`, waiting on an address resolution when
    /// the MAC is not known: an on-link target not heard from lately, or a gateway the
    /// OS gave no hardware address for.
    ///
    /// A next hop that went unanswered on a recent resolution is refused at once; see
    /// [`Resolutions::resolve`].
    fn next_hop_mac(&self, route: &LinkRoute) -> Result<MacAddr, SendError> {
        if let Some(mac) = route.next_hop_mac {
            return Ok(mac);
        }
        let mac = self.resolutions.resolve(&ask_for(route)?)?;
        self.resolver
            .lock()
            .map_err(|_| poisoned("route resolver"))?
            .remember(&route.interface, route.next_hop, mac);
        Ok(mac)
    }

    /// Returns the send handle for `interface`, opening it on first use.
    fn channel_for<'a>(
        &self,
        channels: &'a mut HashMap<String, capture::FrameSender>,
        interface: &str,
    ) -> Result<&'a mut capture::FrameSender, SendError> {
        if !channels.contains_key(interface) {
            let channel = capture::FrameSender::open(interface).map_err(|error| {
                if error.is_exhausted() {
                    SendError::OutOfDescriptors
                } else {
                    SendError::Refused(format!("no datalink channel on {interface}: {error}"))
                }
            })?;
            channels.insert(interface.to_string(), channel);
        }
        Ok(channels.get_mut(interface).unwrap())
    }
}

/// The resolution that finds `route`'s next hop, or why this sender has none to run.
fn ask_for(route: &LinkRoute) -> Result<Ask, SendError> {
    let target = match route.next_hop {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(SendError::Unsupported(
                "IPv6 next-hop resolution (NDP) is not yet implemented",
            ));
        }
    };
    let src_ip = match route.src_ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => {
            return Err(SendError::Unsupported(
                "an IPv4 target cannot be reached from an IPv6 source",
            ));
        }
    };
    Ok(Ask {
        interface: route.interface.clone(),
        src_mac: route.src_mac,
        src_ip,
        target,
    })
}

/// Where a frame sender's resolution of each destination's next hop stands.
///
/// A scan reads this before handing a probe to a frame sender, as it reads the
/// kernel's neighbour table before handing one to a raw socket on Linux. A host whose
/// next hop is still being resolved is sent nothing until resolution concludes, so no
/// send waits and every neighbour is asked at once. A send that waited would hold the
/// whole scan for each dead neighbour in turn.
#[derive(Clone)]
pub(crate) struct LinkNeighbors {
    resolver: Arc<Mutex<NeighborResolver>>,
    resolutions: Arc<Resolutions>,
}

impl LinkNeighbors {
    /// Where the resolution of the next hop for a probe from `src` to `dst` stands,
    /// starting one when nothing is known.
    ///
    /// `None` for a destination this sender does not frame (a send hands it to the
    /// socket behind or refuses it) and for a next hop it cannot resolve. See
    /// [`Resolutions::state`] for the rest.
    pub(crate) fn state(&self, src: IpAddr, dst: IpAddr) -> Option<NeighborState> {
        self.read(src, dst, Resolutions::state)
    }

    /// [`state`](Self::state), but starts a resolution even where one went unanswered
    /// lately; see [`Resolutions::ask_again`].
    pub(crate) fn ask_again(&self, src: IpAddr, dst: IpAddr) -> Option<NeighborState> {
        self.read(src, dst, Resolutions::ask_again)
    }

    /// Where the next hop for a probe from `src` to `dst` stands, using `ask` to read
    /// the resolution of one this sender does not know.
    fn read(
        &self,
        src: IpAddr,
        dst: IpAddr,
        ask: fn(&Arc<Resolutions>, &Ask) -> Option<NeighborState>,
    ) -> Option<NeighborState> {
        let route = self.resolver.lock().ok()?.resolve_from(src, dst)?;
        if route.next_hop_mac.is_some() {
            return Some(NeighborState::Resolved);
        }
        ask(&self.resolutions, &ask_for(&route).ok()?)
    }
}

#[cfg(test)]
impl LinkNeighbors {
    /// A frame sender's view of simulated segments: routed by `resolver`, and
    /// resolving over the [`Segment`] `segment` builds for each link it opens.
    pub(crate) fn simulated(
        resolver: NeighborResolver,
        segment: impl Fn(&str) -> Segment
        + Send
        + Sync
        + std::panic::UnwindSafe
        + std::panic::RefUnwindSafe
        + 'static,
    ) -> Self {
        Self {
            resolver: Arc::new(Mutex::new(resolver)),
            resolutions: Arc::new(Resolutions::over(Box::new(move |interface| {
                Ok(Box::new(segment(interface)) as Box<dyn resolution::ResolutionLink>)
            }))),
        }
    }

    /// A frame sender's view of 192.0.2.0/24 simulated on `interface`, with this host
    /// at [`SIMULATED_HOST`] and only the neighbours in `live` answering, each on the
    /// first request, in real time.
    ///
    /// The interface name keys the neighbours' learned addresses, which the process
    /// shares, so each test names its own.
    pub(crate) fn on_simulated_segment(interface: &str, live: &[std::net::Ipv4Addr]) -> Self {
        use crate::system::interface::LinkAddress;

        let segment = NeighborResolver::on_segment(
            interface,
            MacAddr::new(0x02, 0, 0, 0, 0, 0x50),
            LinkAddress::new(IpAddr::V4(SIMULATED_HOST), 24),
        );
        let live = live.to_vec();
        Self::simulated(segment, move |_| {
            live.iter()
                .fold(Segment::new().in_real_time(), |segment, ip| {
                    let [.., last] = ip.octets();
                    segment.with(
                        *ip,
                        MacAddr::new(0x02, 0, 0, 0, 0, last),
                        Answers::Request(1),
                    )
                })
        })
    }
}

/// This host's address on the segment
/// [`LinkNeighbors::on_simulated_segment`] builds.
#[cfg(test)]
pub(crate) const SIMULATED_HOST: std::net::Ipv4Addr = std::net::Ipv4Addr::new(192, 0, 2, 50);

impl ProbeSender for EthernetSender {
    /// The zone is unused. A frame leaves on the interface its route names, and only
    /// IPv4 destinations are reachable: `next_hop_mac` has no NDP for IPv6.
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        _zone: Option<u32>,
        emission: Emission,
    ) -> Result<(), SendError> {
        // Each step can fail for reasons outside this process (no route, an ARP that
        // went unanswered, an interface that went down mid-scan), so all are refusals
        // carrying the cause.
        if dst.is_loopback()
            && let Some(link) = &self.loopback
        {
            return self.send_on_loopback(link, segment, src, dst, emission);
        }

        (|| -> Result<(), SendError> {
            let route = self
                .resolver
                .lock()
                .map_err(|_| poisoned("route resolver"))?
                .resolve_from(src, dst)
                .ok_or_else(|| {
                    SendError::Unroutable(format!("no Ethernet route from {src} to {dst}"))
                })?;

            let dst_mac = self.next_hop_mac(&route)?;
            let src_mac = spoofed_source_mac(route.src_mac, emission.source_mac);
            let protocol = self.protocols.for_destination(dst);

            // One frame, or several if the caller asked to fragment. A packet that
            // already fits the MTU comes back as a single frame.
            let spec = frame::FrameSpec {
                src_mac,
                dst_mac,
                src,
                dst,
                protocol,
                hop_limit: emission.hop_limit,
            };
            // The framing cannot carry what the caller asked for, so retrying changes
            // nothing.
            let frames = match emission.fragment {
                Some(mtu) => frame::build_fragmented_ethernet_frames(&spec, segment, mtu),
                None => frame::build_ethernet_frame(&spec, segment).map(|frame| vec![frame]),
            }
            .map_err(|error| {
                SendError::Refused(format!("the frame could not be built: {error}"))
            })?;

            let mut channels = self
                .channels
                .lock()
                .map_err(|_| poisoned("datalink channel"))?;
            let channel = self.channel_for(&mut channels, &route.interface)?;
            for frame in &frames {
                channel.send_frame(frame).map_err(|reason| {
                    SendError::Refused(format!("the frame could not be sent: {reason}"))
                })?;
            }
            Ok(())
        })()
    }
}

impl EthernetSender {
    /// Puts a probe on the loopback interface `link` as the frames
    /// [`frame::build_null_loop_frames`] makes. See [`loopback_link`].
    ///
    /// A spoofed hardware address is refused: loopback has no hardware addresses, and
    /// a scan that reports a spoof must have sent one.
    fn send_on_loopback(
        &self,
        link: &str,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        emission: Emission,
    ) -> Result<(), SendError> {
        if emission.source_mac.is_some() {
            return Err(SendError::Unsupported(
                "loopback carries no hardware address to spoof",
            ));
        }
        let spec = frame::IpSpec {
            src,
            dst,
            protocol: self.protocols.for_destination(dst),
            hop_limit: emission.hop_limit,
        };
        let frames =
            frame::build_null_loop_frames(&spec, segment, emission.fragment).map_err(|error| {
                SendError::Refused(format!("the frame could not be built: {error}"))
            })?;

        let mut channels = self
            .channels
            .lock()
            .map_err(|_| poisoned("datalink channel"))?;
        let channel = self.channel_for(&mut channels, link)?;
        for frame in &frames {
            channel.send_frame(frame).map_err(|reason| {
                SendError::Refused(format!("the frame could not be sent: {reason}"))
            })?;
        }
        Ok(())
    }
}

/// The loopback interface, where a frame this sender writes reaches it.
///
/// Only macOS: its loopback interface takes a frame written through BPF (the packet
/// behind the four-byte family word a capture reads) and hands it to the stack as
/// though it had arrived. A scan on the link layer then probes loopback like anything
/// else and the capture reads the reply on that link, which lets a Mac exercise its
/// capture path without sending anything off the machine. Elsewhere it is not needed:
/// a raw socket carries loopback on Linux, and on Windows a frame reaches only what has
/// Ethernet in front of it.
///
/// A run not on the link layer reaches loopback by raw socket or connect; see
/// [`beyond_frames`](crate::system::interface::beyond_frames). Framing it there would
/// open the probe transport's capture, a BPF device on every link, and a Mac has 256
/// such devices: a few concurrent loopback scans would take them all.
fn loopback_link() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    crate::system::interface::interfaces_or_none()
        .into_iter()
        .find(|link| link.is_loopback() && link.is_up())
        .map(|link| link.name().to_string())
}

/// A poisoned lock, returned as a refusal.
///
/// Only reachable if another thread panicked holding the lock, which no critical
/// section here can do. A library still must not `unwrap`: that would turn one
/// panic into a permanent failure of the consumer's send path.
fn poisoned(what: &str) -> SendError {
    SendError::Refused(format!(
        "the {what} lock was poisoned by another thread's panic"
    ))
}

/// The source hardware address a frame should carry: the caller's spoofed one when
/// set, otherwise the sending interface's own.
///
/// Converts from [`model::MacAddr`](crate::model::mac::MacAddr) to pnet's type.
fn spoofed_source_mac(interface: MacAddr, spoofed: Option<crate::model::mac::MacAddr>) -> MacAddr {
    match spoofed {
        Some(mac) => {
            let octets: [u8; 6] = mac.into();
            MacAddr::new(
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
            )
        }
        None => interface,
    }
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

    #[test]
    fn a_spoofed_source_mac_replaces_the_interface_and_converts_faithfully() {
        let interface = MacAddr::new(0x00, 0x11, 0x22, 0x33, 0x44, 0x55);

        // No spoof: the interface's own address.
        assert_eq!(spoofed_source_mac(interface, None), interface);

        // Spoofed: the caller's address, octet for octet. Dropping the octets or
        // keeping the interface's address would send an unspoofed frame while the scan
        // reported a spoof.
        let spoofed = crate::model::mac::MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        assert_eq!(
            spoofed_source_mac(interface, Some(spoofed)),
            MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01)
        );
    }
}
