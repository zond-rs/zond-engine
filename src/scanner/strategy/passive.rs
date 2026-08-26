// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading a link instead of asking it
//!
//! The strategy behind [`listen`](crate::scanner::listen). It opens a capture,
//! reads what the link already carries, and records what that proves. It sends
//! nothing at all — not a probe, not a solicitation, not a single frame — and
//! that is the property the whole design turns on rather than an implementation
//! detail.
//!
//! ## Only ever a positive claim
//!
//! A scanner learns two things from one probe: what a reply says, and what
//! silence says. Silence is informative because the scanner knows a probe went
//! out and knows how long it waited.
//!
//! A listener has neither. It did not send, so it cannot time out. An address it
//! never heard from may be absent, may be silent, may be behind a switch that
//! never forwarded a frame this way, or may have been talking the whole time on
//! a VLAN this link does not carry — four possibilities with no experiment
//! between them.
//!
//! So this raises claims and never lowers one. It records a host as
//! [`Up`](HostStatus::Up) and never as down; it adds a role, a name, a hardware
//! address; and it never contradicts or removes anything. The phase's scope says
//! the same thing in the report — see
//! [`TargetScope::listening_on`](crate::scanner::report::TargetScope::listening_on),
//! which covers no address, so a comparison cannot read a host that stayed quiet
//! as a host that went away.
//!
//! ## What it believes
//!
//! Everything here arrives unauthenticated from whoever cared to send it, which
//! is unlike every other strategy in this module: they correlate each reply
//! against a probe they sent. Anything on a segment can put any source address
//! and any hardware address into a frame.
//!
//! The rule that follows is narrow and is applied at the one place it can be:
//! **a frame is credited to its sender and to nobody else.** A claim about a
//! third address is read for what the *sender* is and never for what the address
//! it names is, which is the same reasoning `local`'s `note_declaration` already
//! applies to an overheard router advertisement.

use std::net::IpAddr;

use async_trait::async_trait;

use crate::model::host::{Host, HostStatus, NetworkRole, StatusReason};
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::protocols::ethernet::{self, Frame};
use crate::protocols::{cdp, lldp};
use crate::scanner::report::{Attachment, AttachmentSource};
use crate::scanner::session::{ScanContext, ScannerKind};
use crate::scanner::strategy::StrategyError;
use crate::scanner::strategy::discovery::{self, DiscoveryProtocol, ProtocolMatch};
use crate::transport::capture::{self, CaptureOptions, CapturedFrame, FrameStream};
use crate::transport::frame::LinkType;
use crate::transport::mac::IntoCoreMac;
use crate::{info, warn};

/// How much of each frame the kernel keeps for a listener.
///
/// **This is the payload boundary, and it is enforced by the kernel rather than
/// by discipline here.** A listener sees traffic belonging to other people, and
/// the honest limit on how much of it this process reads is a limit the process
/// cannot exceed even by mistake. Everything this module concludes comes from
/// link, network and transport headers, plus the first stretch of a
/// control-plane message; none of it needs a session's contents, and a snapshot
/// length that cannot hold them is how that stays true.
///
/// Generous enough for the largest thing actually read — an LLDP advertisement
/// with a long system description — and far short of a payload.
const LISTEN_SNAP_LEN: u32 = 512;

/// How much the kernel may hold for a listening capture before it discards.
///
/// Larger than the default a scan's reply path takes, because the two are
/// bounded by different things. A scan's arrivals are bounded by the probes it
/// sent; a listener's are bounded by the network, which does not slow down
/// because this process is busy.
const LISTEN_BUFFER_BYTES: u32 = 4 * 1024 * 1024;

/// How many frames may wait for the reader at once.
///
/// Multiplied by [`LISTEN_SNAP_LEN`] this is the memory the queue costs, which
/// is why the two are stated together. A full queue stalls the capture thread
/// rather than dropping, so what is lost is counted by the kernel — see
/// [`capture::frames`].
const LISTEN_QUEUE_DEPTH: usize = 4096;

/// How often a listener looks at the abort signal while nothing is arriving.
///
/// It has no schedule of its own to hang the check on. A link can be silent for
/// hours, and a run that noticed the signal only when a frame happened to arrive
/// would be one nobody could stop on exactly the network where stopping matters
/// least urgently and works least well.
const ABORT_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// Which addresses a listener may record findings about.
///
/// A listener has no target set, because it targets nothing. What it has instead
/// is a rule about what may reach the store — and that is the *only* control
/// there is, since unlike every other strategy it cannot narrow what it asks.
///
/// This is the distinction `network roles` §4.4 arrived at from the other
/// direction: what makes a targeted run targeted is what it may **record**, not
/// what it may ask. For a listener there is no asking at all, so recording is
/// where the whole of the scope lives.
#[derive(Debug, Clone, Default)]
pub enum Recording {
    /// Record whatever is heard.
    ///
    /// The honest default for a listener: it was pointed at a link rather than
    /// at addresses, and the link carries what it carries.
    #[default]
    Everything,
    /// Record only findings about these addresses.
    ///
    /// Frames from anything else are still read — a listener cannot decline to
    /// receive — and are dropped without reaching the store.
    Only(IpSet),
}

impl Recording {
    /// Whether a finding about `address` may be recorded.
    fn admits(&self, address: IpAddr) -> bool {
        match self {
            Recording::Everything => true,
            Recording::Only(addresses) => addresses.contains(&address),
        }
    }
}

/// A strategy that reads a link and concludes from it, having sent nothing.
///
/// The third trait beside [`HostScanner`](super::HostScanner) and
/// [`PortScanner`](super::PortScanner), and the shape differs from both because
/// what it does differs from both. A `HostScanner` owns targets and finishes
/// when it has asked about all of them; a `PortScanner` is fed targets and
/// finishes when the stream ends. A listener owns no targets, enumerates
/// nothing, and has no state that can be complete — it finishes when it is told
/// to, and not before.
///
/// Findings go to the [`ScanContext`] it was built with, as they do for the
/// other two: a strategy writes what it found and returns only whether the
/// attempt itself got to the end.
#[async_trait]
pub trait Listener: Send {
    /// Identifies the strategy, so a failure can be attributed to it.
    fn kind(&self) -> ScannerKind;

    /// Reads until the abort signal is raised or the capture ends.
    ///
    /// Returns `Ok` when the run reached its end, including an end forced by
    /// [`ScanHandle::abort`], and `Err` only when the strategy could not do its
    /// job at all.
    async fn observe(&mut self) -> Result<(), StrategyError>;
}

/// Reads one or more links and records what their traffic proves.
pub struct PassiveListener {
    ctx: ScanContext,
    frames: FrameStream,
    /// Kept for as long as this listener runs: dropping it stops the capture
    /// threads.
    capture: capture::CaptureGuard,
    recording: Recording,
    /// The readers, which are the same ones a local sweep interprets its
    /// replies with. A frame that proves a host is there proves it whether or
    /// not this engine asked.
    protocols: Vec<Box<dyn DiscoveryProtocol>>,
}

impl PassiveListener {
    /// Opens a capture on each of `links` and reads it.
    ///
    /// Fails only when no link could be captured, since a listener with nothing
    /// to listen to is not one.
    pub fn open(
        links: &[Zone],
        recording: Recording,
        ctx: ScanContext,
    ) -> Result<Self, StrategyError> {
        let options = CaptureOptions::for_link_traffic(Self::filter())
            .with_snaplen(LISTEN_SNAP_LEN)
            .with_buffer_bytes(LISTEN_BUFFER_BYTES);

        let (frames, capture) =
            capture::frames(links, &options, LISTEN_QUEUE_DEPTH).map_err(|_| {
                StrategyError::Interface {
                    interface: links.iter().map(Zone::name).collect::<Vec<_>>().join(", "),
                    reason: "no link could be captured (listening needs root)",
                }
            })?;

        Ok(Self::over(frames, capture, recording, ctx))
    }

    /// Builds a listener over an already-open frame stream.
    ///
    /// The seam a test drives a listener through: push frames onto the sending
    /// half and they arrive as though captured, with no interface and no
    /// privileges involved.
    pub fn over(
        frames: FrameStream,
        capture: capture::CaptureGuard,
        recording: Recording,
        ctx: ScanContext,
    ) -> Self {
        Self {
            ctx,
            frames,
            capture,
            recording,
            protocols: discovery::sweep_protocols(),
        }
    }

    /// What a listener's capture admits.
    ///
    /// Everything the readers below can use, and nothing else. Wider than a
    /// sweep's — it takes TCP, to see which endpoints are serving somebody —
    /// and still a filter rather than the whole wire, because a capture that
    /// admits everything copies a link into this process to discard almost all
    /// of it.
    fn filter() -> String {
        let mut clauses: Vec<&'static str> = discovery::sweep_protocols()
            .iter()
            .map(|protocol| protocol.capture_clause())
            .collect();

        clauses.extend([
            // The announcements, which are what say where this machine is.
            "(ether proto 0x88cc)",
            "(ether dst 01:00:0c:cc:cc:cc)",
            // Names somebody else's lookup put on the wire.
            "(udp port 5353)",
            "(udp port 53)",
            // The handshakes that say an endpoint served a real client. Only
            // the server's half of one establishes a listener; see
            // `read_tcp`.
            "(tcp)",
        ]);

        clauses.sort_unstable();
        clauses.dedup();
        clauses.join(" or ")
    }

    /// Reads one frame for everything it proves.
    ///
    /// Every reader is tried: a frame can carry more than one finding, and
    /// stopping at the first would make what is recorded depend on the order
    /// they happen to be written in.
    fn read(&mut self, captured: &CapturedFrame) {
        if captured.link != LinkType::Ethernet {
            return;
        }
        let Ok(frame) = ethernet::parse(&captured.bytes) else {
            return;
        };

        if self.read_announcement(&frame, captured) {
            return;
        }
        self.read_presence(&frame);
    }

    /// Records where this machine is plugged in, where the frame says so.
    ///
    /// Returns whether the frame was an announcement.
    ///
    /// The attachment is recorded whatever [`Recording`] says, because it is not
    /// a finding about an address: it is a relation between this machine and the
    /// equipment on the far end of its own cable, and no address filter has an
    /// opinion about that.
    fn read_announcement(&mut self, frame: &Frame<'_>, captured: &CapturedFrame) -> bool {
        let source = frame.source().into_core();

        let (attachment, roles) = if let Some(advertisement) = lldp::parse(frame) {
            let mut attachment = Attachment::new(
                captured.zone.clone(),
                AttachmentSource::Lldp,
                captured.observed_at,
            )
            .with_device_mac(source);
            if let Some(name) = advertisement.system_name {
                attachment = attachment.with_device_name(name);
            }
            if let Some(lldp::Identifier::Text(port)) = advertisement.port_id {
                attachment = attachment.with_port(port);
            }
            if let Some(vlan) = advertisement.port_vlan {
                attachment = attachment.with_native_vlan(vlan);
            }
            if let Some(address) = advertisement.management_address {
                attachment = attachment.with_management_address(address);
            }

            let mut roles = Vec::new();
            if let Some(capabilities) = advertisement.capabilities {
                if capabilities.is_bridge() {
                    roles.push(NetworkRole::Switch);
                }
                if capabilities.is_router() {
                    roles.push(NetworkRole::Router);
                }
            }
            (attachment, roles)
        } else if let Some(announcement) = cdp::parse(frame) {
            let mut attachment = Attachment::new(
                captured.zone.clone(),
                AttachmentSource::Cdp,
                captured.observed_at,
            )
            .with_device_mac(source);
            if let Some(name) = announcement.device_id {
                attachment = attachment.with_device_name(name);
            }
            if let Some(port) = announcement.port_id {
                attachment = attachment.with_port(port);
            }
            if let Some(vlan) = announcement.native_vlan {
                attachment = attachment.with_native_vlan(vlan);
            }
            if let Some(address) = announcement.address {
                attachment = attachment.with_management_address(address);
            }

            let mut roles = Vec::new();
            if let Some(capabilities) = announcement.capabilities {
                if capabilities.is_switch() {
                    roles.push(NetworkRole::Switch);
                }
                if capabilities.is_router() {
                    roles.push(NetworkRole::Router);
                }
            }
            (attachment, roles)
        } else {
            return false;
        };

        info!(
            verbosity = 1,
            "{} says this machine is on {}{}",
            captured.zone,
            attachment.device_name().unwrap_or("an unnamed device"),
            match attachment.port() {
                Some(port) => format!(" port {port}"),
                None => String::new(),
            },
        );

        // The device's management address is the only address an announcement
        // names, and the roles belong to the machine that sent the frame. Where
        // the two agree there is a host to put them on; where the device
        // advertised none, the attachment is the whole of the record and that is
        // the ordinary case for a switch with no address on this segment.
        if let Some(address) = attachment.management_address()
            && self.recording.admits(address)
        {
            let mut host = Host::new(address);
            host.record_mac(source);
            for role in roles {
                host.add_network_role(role);
            }
            self.merge(host);
        }

        self.ctx.record_attachment(attachment);
        true
    }

    /// Records that whoever sent this frame is present, where a reader
    /// recognises it.
    ///
    /// The readers are a local sweep's own, used unchanged: a neighbour
    /// advertisement, an ARP frame or a DHCP server's answer proves its sender
    /// is there, and it proves it whether or not this engine asked the question
    /// that drew it.
    fn read_presence(&mut self, frame: &Frame<'_>) {
        let Ok(source) = crate::protocols::source_address(frame) else {
            return;
        };
        if !self.recording.admits(source) {
            return;
        }

        for protocol in &self.protocols {
            let Ok(reading) = protocol.interpret(frame) else {
                continue;
            };
            if matches!(reading.matched, ProtocolMatch::Unhandled) {
                continue;
            }

            // Credited to the sender, never to an address the frame merely
            // names. A neighbour advertisement's target and a DHCP message's
            // server identifier are claims about somebody else, and a listener
            // has no probe outstanding to check either against.
            let mut host = Host::new(source);
            host.record_mac(frame.source().into_core());
            host.record_evidence(
                HostStatus::Up,
                StatusReason::basic(protocol.status_protocol()),
            );
            if let Some(role) = reading.declared {
                host.add_network_role(role);
            }
            self.merge(host);
            return;
        }
    }

    /// Folds a finding into the store, promoting rather than replacing.
    ///
    /// [`Host::merge`] is what keeps a listener from ever lowering a claim: it
    /// promotes status and accumulates addresses, hardware addresses and roles,
    /// and where two findings are equally good the one already recorded wins.
    fn merge(&self, host: Host) {
        let key = host.scoped_ip();
        self.ctx.write_host(key, |existing| {
            existing.merge(host);
            true
        });
    }
}

#[async_trait]
impl Listener for PassiveListener {
    fn kind(&self) -> ScannerKind {
        ScannerKind::Passive
    }

    async fn observe(&mut self) -> Result<(), StrategyError> {
        // A listener has no schedule of its own, so the abort flag is checked on
        // a ticker rather than between units of work: there may be no next frame
        // for hours, and a run that only noticed the signal when something
        // happened to arrive would be a run nobody could stop on a quiet link.
        let mut stopping = tokio::time::interval(ABORT_POLL);
        stopping.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

        loop {
            if self.ctx.handle.should_stop() {
                break;
            }

            tokio::select! {
                frame = self.frames.recv() => match frame {
                    Some(frame) => self.read(&frame),
                    // Every capture thread has ended, which for a listener is
                    // the end of the run rather than a fault: there is nothing
                    // left that could speak.
                    None => break,
                },
                _ = stopping.tick() => {}
            }
        }

        if let Some(counts) = self.capture.counts()
            && counts.dropped > 0
        {
            warn!(
                "the capture discarded {} of {} frames it admitted, so what this \
                 phase did not hear is larger than what it did",
                counts.dropped, counts.received,
            );
        }

        Ok(())
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
    use crate::scanner::session::ScanSession;
    use crate::scanner::strategy::discovery::tests::{
        PEER_MAC, advertisement_body, arp_reply_frame, dhcp_reply_frame, ndp_frame,
    };
    use std::net::Ipv4Addr;
    use std::time::SystemTime;

    fn zone() -> Zone {
        Zone::new(7, "sim0")
    }

    fn captured(bytes: Vec<u8>) -> CapturedFrame {
        CapturedFrame {
            zone: zone(),
            link: LinkType::Ethernet,
            bytes,
            observed_at: SystemTime::UNIX_EPOCH,
        }
    }

    /// A listener over a stream a test pushes frames onto, with no capture
    /// behind it and no privileges involved.
    fn listening(recording: Recording) -> (PassiveListener, ScanContext) {
        let (_session, ctx) = ScanSession::new();
        let (_tx, rx) = tokio::sync::mpsc::channel(16);
        (
            PassiveListener::over(rx, capture::CaptureGuard::noop(), recording, ctx.clone()),
            ctx,
        )
    }

    /// The listener's filter has to admit everything its readers can use, and it
    /// fails silently otherwise: a reader that is never given a frame and one
    /// that recognises nothing are indistinguishable from the loop.
    ///
    /// The sweep's equivalent lives beside the sweep. This one is wider — it
    /// takes TCP, to see which endpoints are serving somebody — so it needs its
    /// own.
    #[test]
    fn the_listen_filter_admits_every_frame_a_listener_can_read() {
        let filter = PassiveListener::filter();
        let program = pcap::Capture::dead(pcap::Linktype::ETHERNET)
            .expect("a dead capture")
            .compile(&filter, true)
            .unwrap_or_else(|e| panic!("the listen filter `{filter}` does not compile: {e}"));

        let lldp = crate::protocols::ethernet::create_header(
            PEER_MAC,
            pnet::datalink::MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E),
            lldp::ETHERTYPE,
        );

        let readable: [(&str, Vec<u8>); 5] = [
            ("an ARP frame", arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2))),
            (
                "a neighbour advertisement",
                ndp_frame(&advertisement_body(
                    std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2),
                    0,
                )),
            ),
            (
                "a DHCP server reply",
                dhcp_reply_frame(Ipv4Addr::new(192, 168, 1, 1), None),
            ),
            ("an LLDP advertisement", lldp),
            (
                "a TCP segment, which is how an endpoint is seen serving somebody",
                {
                    let datagram = crate::protocols::craft::Packet::new()
                        .push(crate::protocols::craft::Ipv4::new(
                            Ipv4Addr::new(10, 0, 0, 5),
                            Ipv4Addr::new(10, 0, 0, 9),
                        ))
                        .push(crate::protocols::craft::Tcp::new(443, 51234))
                        .build()
                        .expect("a test segment");
                    [
                        crate::protocols::ethernet::create_header(
                            PEER_MAC,
                            PEER_MAC,
                            pnet::packet::ethernet::EtherTypes::Ipv4,
                        ),
                        datagram,
                    ]
                    .concat()
                },
            ),
        ];

        for (what, frame) in readable {
            assert!(
                program.filter(&frame),
                "the listen filter rejects {what}, so a listener would never see \
                 one: {filter}"
            );
        }
    }

    /// A frame is credited to the machine that sent it, and to no address the
    /// frame merely names.
    ///
    /// A sweep may credit the address a reply is *about* — it asked about that
    /// address, so a reply from one of the host's other addresses still answers
    /// the question. A listener asked nothing, so it has no question a third
    /// address could be answering and nothing to check the claim against. The
    /// two cases below are the ones where a frame names somebody else:
    /// a neighbour advertisement carries a target, and a DHCP reply carries a
    /// server identifier that a relay agent makes a different machine entirely.
    #[test]
    fn a_frame_credits_its_sender_and_no_address_it_merely_names() {
        let (mut listener, ctx) = listening(Recording::Everything);

        // Sent from fe80::2, naming fe80::99 as its target.
        let target = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0x99);
        listener.read(&captured(ndp_frame(&advertisement_body(target, 0))));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(hosts.len(), 1, "one frame, one sender, one host");
        assert_eq!(
            hosts[0].primary_ip(),
            IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2)),
            "the address the frame came from, not the one it named"
        );

        // And the same for a relayed DHCP answer, where the sender is the relay
        // and the message names a server on another segment.
        let (mut listener, ctx) = listening(Recording::Everything);
        let relay = Ipv4Addr::new(192, 168, 1, 1);
        let elsewhere = Ipv4Addr::new(10, 0, 0, 53);
        listener.read(&captured(dhcp_reply_frame(elsewhere, Some(relay))));

        let hosts = ctx.hosts_snapshot();
        assert_eq!(hosts.len(), 1);
        assert_eq!(
            hosts[0].primary_ip(),
            IpAddr::V4(relay),
            "the machine that sent the frame, not the one option 54 named"
        );
    }

    /// The only control a listener has. It cannot narrow what it hears, so a
    /// caller who wants a bounded record gets it at the point findings are
    /// written — which is where `network roles` §4.4 put the same rule.
    #[test]
    fn a_recording_filter_keeps_out_what_the_link_carries_anyway() {
        let mut wanted = IpSet::new();
        wanted.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7)));

        let (mut listener, ctx) = listening(Recording::Only(wanted));
        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2))));

        assert_eq!(
            ctx.host_count(),
            0,
            "the frame was heard, and recording it was declined"
        );

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 7))));
        assert_eq!(ctx.host_count(), 1, "and the one in scope was kept");
    }

    /// A listener may raise a claim and never lower one.
    ///
    /// It sent nothing, so it cannot have timed anything out, so there is no
    /// silence it is entitled to read as absence. This is the rule the whole
    /// phase turns on, and the one a future edit is most likely to break by
    /// making a reader "correct" a host it disagrees with.
    #[test]
    fn a_listener_never_lowers_a_claim_already_on_the_record() {
        let (mut listener, ctx) = listening(Recording::Everything);

        let address = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let mut known = Host::new(address);
        known.set_status(HostStatus::Up);
        known.set_hostname(Some("already-known".to_owned()));
        ctx.write_host(known.scoped_ip(), |host| {
            host.merge(known);
            true
        });

        listener.read(&captured(arp_reply_frame(Ipv4Addr::new(10, 0, 0, 2))));

        let host = ctx
            .hosts_snapshot()
            .into_iter()
            .find(|host| host.primary_ip() == address)
            .expect("the host is still there");
        assert_eq!(host.status(), HostStatus::Up);
        assert_eq!(
            host.hostname(),
            Some("already-known"),
            "a listener added to the record and took nothing off it"
        );
    }
}
