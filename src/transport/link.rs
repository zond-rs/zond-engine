// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Layer-2 (Ethernet) Send Backend
//!
//! A [`ProbeSender`] that builds and
//! emits complete Ethernet frames itself, rather than handing a segment to a
//! raw socket and letting the kernel route it.
//!
//! Two situations need this:
//!
//! - **Windows**, where the OS blocks raw-socket TCP sends outright, so the
//!   only way to emit a SYN probe is to write the frame at the link layer.
//! - **Deliberate host-stack bypass**: crafting the frame end to end (source
//!   MAC included) sidesteps the local firewall and connection-tracking that
//!   a raw-socket send still traverses.
//!
//! It leans on [`NeighborResolver`] to decide, per packet, which interface to
//! send from and what the next-hop MAC is: the interface holding the packet's
//! source address, the gateway the OS names for it for off-link targets, and an
//! ARP resolution for on-link ones, run beside every other one the sender has
//! in flight rather than one at a time. A packet whose source only a
//! tunnel holds has no Ethernet route, and is refused rather than framed onto a
//! physical link the tunnel was meant to carry it past.
//!
//! On portability: on-link IPv6 currently returns an error rather than performing
//! NDP neighbor solicitation, while off-link IPv6 works since the gateway's MAC
//! comes from the OS. Wiring up NDP is the remaining gap.

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

/// A Layer-2 send backend. Interfaces' send handles are opened lazily on first
/// use and reused thereafter.
pub struct EthernetSender {
    /// Shared with the [`LinkNeighbors`] a scan reads, which routes a
    /// destination to its next hop the way a send does.
    resolver: Arc<Mutex<NeighborResolver>>,
    /// The address resolutions this sender runs, shared with the same
    /// [`LinkNeighbors`].
    resolutions: Arc<Resolutions>,
    /// A send-only handle per interface. The resolutions read ARP on channels
    /// of their own, so nothing here is ever read and a filter that admits
    /// nothing keeps its buffer empty.
    channels: Mutex<HashMap<String, capture::FrameSender>>,
    /// The IP protocol numbers to stamp into the headers this sender builds,
    /// one per address family. Fixed per sender because a transport carries one
    /// kind of probe; see [`EthernetSender::from_system`].
    protocols: IpProtocols,
    /// The loopback interface, where this sender reaches it; see
    /// [`loopback_link`].
    loopback: Option<String>,
}

impl EthernetSender {
    /// Builds a sender over the system's Ethernet-capable interfaces, emitting
    /// segments as `protocols` says for the family being addressed.
    ///
    /// Unlike the raw-socket sender, this one writes the IP header itself, so
    /// nothing else can tell it what it is carrying: the segment is opaque
    /// bytes by the time it arrives. The protocols are fixed at construction
    /// rather than passed per send because a transport is opened for one
    /// `ProbeKind` and carries only that kind's probes. They are a pair because a
    /// kind carrying ICMP carries two different protocol numbers and only the
    /// destination says which. A wrong number here is invisible
    /// locally and fatal remotely: the datagram arrives and is handed to the
    /// wrong protocol handler, so it is simply never answered.
    ///
    /// Returns `None` if the host has no Ethernet-capable interface (only
    /// tunnels or loopback), so the caller can fall back to the raw-IP path
    /// rather than stand up a backend that can never send.
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

    /// Where this sender's resolution of each destination's next hop stands,
    /// for a scan that holds its probes while a resolution runs rather than
    /// have a send wait on it.
    pub(crate) fn neighbors(&self) -> LinkNeighbors {
        LinkNeighbors {
            resolver: Arc::clone(&self.resolver),
            resolutions: Arc::clone(&self.resolutions),
        }
    }

    /// Determines the next-hop MAC for `route`, waiting on an address
    /// resolution for a next hop whose MAC is not already known: an on-link
    /// target not heard from lately, or a gateway the OS gave no hardware
    /// address for.
    ///
    /// A next hop that went unanswered on a recent resolution is refused at
    /// once rather than asked and waited on again; see [`Resolutions::resolve`].
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

/// The resolution that finds `route`'s next hop, or why this sender has none
/// to run.
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
/// What a scan reads before it hands a probe to a frame sender, as it reads
/// the kernel's neighbour table before handing one to a raw socket on Linux:
/// a host whose next hop is still being asked for is sent nothing until the
/// asking concludes, so no send waits on a resolution and every neighbour a
/// scan meets is asked at once. A send that did wait would hold the whole scan
/// for each dead neighbour in turn.
#[derive(Clone)]
pub(crate) struct LinkNeighbors {
    resolver: Arc<Mutex<NeighborResolver>>,
    resolutions: Arc<Resolutions>,
}

impl LinkNeighbors {
    /// Where the resolution of the next hop a probe from `src` to `dst` is
    /// framed to stands, starting one when nothing is known of it.
    ///
    /// `None` for a destination this sender does not frame, which a send
    /// hands to the socket behind it or refuses, and for a next hop it cannot
    /// resolve; neither is anything to hold a probe for. See
    /// [`Resolutions::state`] for the rest.
    pub(crate) fn state(&self, src: IpAddr, dst: IpAddr) -> Option<NeighborState> {
        let route = self.resolver.lock().ok()?.resolve_from(src, dst)?;
        if route.next_hop_mac.is_some() {
            return Some(NeighborState::Resolved);
        }
        self.resolutions.state(&ask_for(&route).ok()?)
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

    /// A frame sender's view of 192.0.2.0/24 simulated on `interface`, with
    /// this host at [`SIMULATED_HOST`] and only the neighbours in `live`
    /// answering, each the first request it is sent, in real time.
    ///
    /// The interface names the neighbours' learned addresses, which the
    /// process shares, so each test names one of its own.
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
    /// The zone is unused here. A frame this sender builds leaves on the
    /// interface its own route names, and the destination it can reach that way
    /// is IPv4: `next_hop_mac` has no NDP to resolve an IPv6 neighbour with.
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        _zone: Option<u32>,
        emission: Emission,
    ) -> Result<(), SendError> {
        // Every step here can fail for a reason outside this process - no route,
        // a neighbour that never answered our ARP, an interface that went down
        // mid-scan - so they are all refusals carrying the cause, not claims
        // that the transport is incapable.
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

            // One frame, or several if the caller asked to fragment. A packet
            // that already fits the requested MTU comes back as a single frame,
            // so the fragmenting path is not a second code path for the ordinary
            // case.
            let spec = frame::FrameSpec {
                src_mac,
                dst_mac,
                src,
                dst,
                protocol,
                hop_limit: emission.hop_limit,
            };
            // A packet this transport cannot express, as against a network that
            // would not take it: the caller asked for something the framing
            // cannot carry, and asking again changes nothing.
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
    /// A spoofed hardware address is refused rather than dropped, since a
    /// link with no hardware addresses has nowhere to carry one, and a scan
    /// that reports it spoofed has to have done so.
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

/// The loopback interface where a frame this sender writes reaches it, and
/// `None` where none does.
///
/// macOS, whose loopback interface takes a frame written through BPF, the
/// packet behind the four-byte family word a capture of it reads, and hands it
/// to the stack as though it had arrived. So a scan that chose the link layer
/// probes loopback as it probes anything else, and the capture reads the reply
/// on that link as it reads any other, which is how a Mac exercises its own
/// capture path without sending anything past itself. Elsewhere no run needs
/// it: a raw socket carries loopback on Linux, and on Windows a frame reaches
/// only what has Ethernet in front of it.
///
/// A run that did not choose the link layer still reaches loopback another
/// way, by the raw socket where it holds one and by connect where it holds
/// frames alone; see
/// [`beyond_frames`](crate::system::interface::beyond_frames). Framing it
/// there would open the probe transport's capture, a BPF device on every link
/// the machine has, for a question a connect answers as well, and a Mac has
/// 256 such devices: a few loopback scans at once take them all.
fn loopback_link() -> Option<String> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    crate::system::interface::interfaces()
        .into_iter()
        .find(|link| link.is_loopback() && link.is_up())
        .map(|link| link.name().to_string())
}

/// A poisoned lock, carried as a refusal rather than taken as a panic.
///
/// Reachable only when another thread panicked while holding the lock, which no
/// critical section in this module can do: each is a few statements over data it
/// owns. It is carried anyway because this is a library. `unwrap` here would
/// turn one thread's panic into a permanent failure of the consumer's send path,
/// with every later probe panicking and nothing they could catch, retry, or read
/// a cause from.
fn poisoned(what: &str) -> SendError {
    SendError::Refused(format!(
        "the {what} lock was poisoned by another thread's panic"
    ))
}

/// The source hardware address a frame should carry: the caller's spoofed one
/// when set, otherwise the sending interface's own.
///
/// The evasion profile speaks [`model::MacAddr`](crate::model::mac::MacAddr) and
/// the frame builder speaks pnet's, so this is the one place they meet.
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

        // No spoof: the interface's own address is used.
        assert_eq!(spoofed_source_mac(interface, None), interface);

        // Spoofed: the caller's address is used, octet for octet across the
        // model/pnet boundary. A mutant that dropped the octets or kept the
        // interface's address would send an unspoofed frame while the scan
        // reported a spoof.
        let spoofed = crate::model::mac::MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        assert_eq!(
            spoofed_source_mac(interface, Some(spoofed)),
            MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01)
        );
    }
}
