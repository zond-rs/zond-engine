// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Probe Transport
//!
//! One handle the raw scanners send probes through and receive replies from, whatever
//! carries those packets to the wire.
//!
//! Sending and receiving use separate mechanisms, because the constraints differ by
//! direction and by OS:
//!
//! - **Receiving** always goes through a `libpcap` capture
//!   ([`crate::transport::capture`]). A raw Layer-4 socket receives replies on Linux
//!   but not on macOS/BSD, whose kernels never hand TCP/UDP to raw sockets; capturing
//!   at the link layer works everywhere.
//! - **Sending** goes through a [`ProbeSender`]. [`RawIpSender`] emits segments over a
//!   raw Layer-4 socket, which sends fine on every supported Unix and lets the kernel
//!   handle routing, ARP/NDP and fragmentation. The Ethernet sender builds frames
//!   itself, for Windows (which blocks raw TCP sends) or to bypass the host stack.
//!
//! [`ProbeTransport`] owns a `Box<dyn ProbeSender>` and a capture-fed receive stream,
//! and every scanner depends only on those two.

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use pnet_packet::Packet;
use pnet_packet::ip::IpNextHeaderProtocols;

use crate::model::capture::CaptureCounts;
use crate::model::ip::scoped::Zone;
use crate::model::ip::set::IpSet;
use crate::model::mac::MacAddr;
use crate::model::port::Protocol;
use crate::system::interface::{Link, RoutedTargets};
use crate::transport::capture::{self, CaptureGuard, CaptureOptions, CaptureStream};
use crate::transport::kernel_neighbors::KernelNeighbors;
use crate::transport::link::{EthernetSender, LinkNeighbors};
use crate::transport::raw::{self, TransportSenderHandle, TransportType};

/// How many captured segments may wait for a scanner to read them.
///
/// Deep enough that a burst of real replies never stalls the reader, and shallow
/// enough that traffic the filter could not narrow stays bounded: at
/// [`REPLY_SNAP_LEN`](capture::REPLY_SNAP_LEN) a full queue is a few megabytes. See
/// [`capture::segments`] for which filters leave that possible.
const REPLY_QUEUE_DEPTH: usize = 4096;

/// The error [`SendMode::from_str`] returns, carrying the valid names so a front end
/// can print it verbatim.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown send mode '{input}', expected one of: auto, raw_socket, ethernet")]
pub struct UnknownSendMode {
    /// What the caller wrote.
    pub input: String,
}

/// How the privileged (raw) scanners put probe packets on the wire.
///
/// Affects only the raw-socket SYN paths; the unprivileged TCP-connect fallback and
/// the on-link ARP/ICMPv6 [`LocalScanner`](crate::scanner) discovery ignore it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SendMode {
    /// Pick per platform. On Linux, a raw Layer-4 socket, which the kernel routes,
    /// ARPs and fragments for, and which works through VPN tunnels. On Windows,
    /// self-built Layer-2 Ethernet frames, since the OS blocks raw-socket TCP sends.
    /// On macOS, frames first with the socket behind them: a large scan's raw sends
    /// are accepted there and a quarter dropped before the wire, and an unprivileged
    /// run has no socket to fall back to.
    #[default]
    Auto,
    /// Force a raw Layer-4 socket regardless of platform.
    RawSocket,
    /// Force self-built Layer-2 Ethernet frames, bypassing the host IP stack (and the
    /// local firewall and connection tracking a raw-socket send still passes through).
    /// Requires an Ethernet-capable interface and can't reach tunnel-only
    /// destinations, or loopback except on macOS, whose loopback interface takes a
    /// frame too.
    Ethernet,
}
impl SendMode {
    /// Every mode, in the order a front end should offer them.
    pub const ALL: &'static [Self] = &[SendMode::Auto, SendMode::RawSocket, SendMode::Ethernet];

    /// The name this mode is written under, wherever it arrives as text.
    pub const fn name(self) -> &'static str {
        match self {
            SendMode::Auto => "auto",
            SendMode::RawSocket => "raw_socket",
            SendMode::Ethernet => "ethernet",
        }
    }

    /// Whether a transport this process opens in this mode reaches what a self-built
    /// frame cannot: loopback, this host's own addresses, a target the kernel routes
    /// through a tunnel, and an IPv6 neighbour.
    ///
    /// A raw socket reaches all of it, since the kernel carries the packet; a frame
    /// reaches what has Ethernet in front of it. `Auto` is whichever this platform
    /// opens: the socket on Linux, frames alone on Windows, and on macOS frames with
    /// the socket behind them for a process allowed to open one. An unprivileged run
    /// there with the BPF devices given to its group has only the frames.
    pub(crate) fn reaches_past_frames(self) -> bool {
        match self {
            SendMode::RawSocket => true,
            SendMode::Ethernet => false,
            SendMode::Auto => {
                #[cfg(windows)]
                {
                    false
                }
                #[cfg(target_os = "macos")]
                {
                    crate::system::privilege::can_send_raw()
                }
                #[cfg(not(any(windows, target_os = "macos")))]
                {
                    true
                }
            }
        }
    }
}
impl fmt::Display for SendMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}
impl FromStr for SendMode {
    type Err = UnknownSendMode;

    /// Parses a mode name, ignoring case and surrounding whitespace, so text input (an
    /// argument, a form field, a settings file) needs no mapping table of its own.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::transport::probe::SendMode;
    ///
    /// assert_eq!("Ethernet".parse(), Ok(SendMode::Ethernet));
    /// assert!("layer2".parse::<SendMode>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().to_ascii_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|mode| mode.name() == name)
            .ok_or_else(|| UnknownSendMode {
                input: s.to_string(),
            })
    }
}

/// Which kind of raw probe traffic a [`ProbeTransport`] carries. Decides both the raw
/// sockets opened for sending and the kernel BPF filter that picks which captured
/// frames are copied to userspace.
#[non_exhaustive]
#[derive(Debug, Clone, Copy)]
pub enum ProbeKind {
    /// TCP SYN probes and their SYN+ACK / RST replies, over IPv4 and IPv6, where the
    /// sender picks a fresh source port per probe.
    TcpSyn,
    /// TCP port probes and their replies, for a scan that sends every probe from one
    /// source port.
    TcpProbe {
        /// The port every probe in the scan leaves from, and so the port its replies
        /// come back to. A fixed port makes the TCP half of the filter expressible for
        /// both families: `dst port` compiles over IPv6 where the flag test in
        /// [`ProbeKind::TcpSyn`] cannot, so the scan sees only its own answers.
        reply_port: u16,
        /// Whether ICMP destination-unreachable messages are wanted as well.
        ///
        /// They tell a probe it was stopped in the path, but an ICMP error carries no
        /// ports of its own (the probe it refers to is quoted in its payload), so
        /// admitting them means admitting all ICMP on every captured interface and
        /// matching it in userspace. Only a scan whose verdicts depend on that
        /// evidence should pay for it.
        icmp_errors: bool,
    },
    /// UDP service probes (DNS / mDNS) and their replies, over IPv4.
    UdpResolve,
    /// ICMP echo requests and the replies and errors they draw, over both address
    /// families.
    ///
    /// For asking a host something its TCP stack cannot be made to answer. A host
    /// with no open and no closed port still answers a ping, and the reply reflects
    /// the same stack.
    IcmpEcho {
        /// The identifier every echo in the scan carries, and so the one its replies
        /// carry back.
        ///
        /// RFC 792 and RFC 4443 §4.2 require a reply to echo the identifier and
        /// sequence unchanged, which is the only thing separating this scan's answers
        /// from every other ping on the host. It cannot be expressed in a kernel
        /// filter, since it sits past a header of variable length over IPv6, so it is
        /// matched in userspace against this field.
        identifier: u16,
    },
    /// SCTP port probes and the chunks they draw, over both address families.
    ///
    /// One kind for both techniques: an INIT and a COOKIE-ECHO are the same protocol
    /// from the same port, so one filter serves both.
    Sctp {
        /// The port every probe in the scan leaves from, and so the port its answers
        /// come back to.
        ///
        /// Fixed for the same reason as [`UdpProbe`](Self::UdpProbe)'s: the kernel
        /// filter narrows on it, and the packet quoted inside an ICMP error is checked
        /// against it.
        reply_port: u16,
    },
    /// Bare datagrams of one arbitrary IP protocol, and the ICMP messages they draw.
    ///
    /// What an [IP protocol scan](crate::scanner::strategy::protocols) sends. The
    /// number is the next-header value the probe carries, and is itself what the scan
    /// asks about.
    ///
    /// The number does not narrow the filter, which is the same for every number. Most
    /// protocols worth asking about have no header this crate parses, no ports and no
    /// reply of their own; the host's ICMP answers, and an ICMP message names what
    /// provoked it only in the packet it quotes. So errors are admitted whole and
    /// matched against the quotation in userspace, as [`UdpProbe`](Self::UdpProbe)
    /// does.
    IpProtocol {
        /// The next-header value the probes carry: the protocol the scan asks whether
        /// the host accepts.
        number: u8,
    },
    /// UDP port probes and their ICMP unreachable / direct UDP replies.
    UdpProbe {
        /// The source port every probe in the scan is sent from, and so the
        /// destination port its direct replies come back to. A fixed port lets the
        /// kernel filter the UDP half down to this scan's own traffic; otherwise the
        /// only expressible filter is all UDP, mostly other people's packets on a busy
        /// host.
        reply_port: u16,
    },
}

impl ProbeKind {
    /// The kind in words, with its article, as a message names the traffic a transport
    /// was opened for: `a UDP probe`, `an ICMP echo`. The fields are left out.
    pub(crate) const fn spoken(self) -> &'static str {
        match self {
            ProbeKind::TcpSyn => "a TCP SYN",
            ProbeKind::TcpProbe { .. } => "a TCP probe",
            ProbeKind::UdpResolve => "a UDP resolver",
            ProbeKind::IcmpEcho { .. } => "an ICMP echo",
            ProbeKind::Sctp { .. } => "an SCTP probe",
            ProbeKind::IpProtocol { .. } => "an IP protocol probe",
            ProbeKind::UdpProbe { .. } => "a UDP probe",
        }
    }

    /// The port a transport for this kind admits replies to, where the kind fixes one.
    const fn reply_port(self) -> Option<u16> {
        match self {
            ProbeKind::TcpProbe { reply_port, .. }
            | ProbeKind::UdpProbe { reply_port }
            | ProbeKind::Sctp { reply_port } => Some(reply_port),
            ProbeKind::TcpSyn
            | ProbeKind::UdpResolve
            | ProbeKind::IcmpEcho { .. }
            | ProbeKind::IpProtocol { .. } => None,
        }
    }

    /// Whether a transport opened for this kind hears the answers a port scan of
    /// `protocol` reads.
    ///
    /// A port scan over a transport that does not would read every answer as silence,
    /// which is a verdict, so the mismatch is refused. Either TCP kind carries a TCP
    /// scan: both admit the resets and SYN+ACKs it reads. A UDP scan needs its own
    /// kind, since the resolver's admits only name-service replies.
    pub(crate) const fn carries_port_scan(self, protocol: Protocol) -> bool {
        match protocol {
            Protocol::Tcp => matches!(self, ProbeKind::TcpSyn | ProbeKind::TcpProbe { .. }),
            Protocol::Udp => matches!(self, ProbeKind::UdpProbe { .. }),
            Protocol::Sctp => matches!(self, ProbeKind::Sctp { .. }),
        }
    }

    /// The raw-socket transport type used for the send half.
    fn transport_type(self) -> TransportType {
        match self {
            ProbeKind::TcpSyn | ProbeKind::TcpProbe { .. } => TransportType::TcpLayer4,
            ProbeKind::UdpResolve | ProbeKind::UdpProbe { .. } => TransportType::UdpLayer4,
            ProbeKind::Sctp { .. } => TransportType::SctpLayer4,
            ProbeKind::IcmpEcho { .. } => TransportType::IcmpLayer4,
            ProbeKind::IpProtocol { number } => TransportType::IpProtocol(number),
        }
    }

    /// The IP protocol numbers this kind's probes carry, one per address family, for a
    /// sender that writes the IP header itself.
    ///
    /// The raw-socket path takes the number from the socket's protocol; a Layer-2
    /// sender builds the header and has only this. A wrong number is invisible
    /// locally: the datagram reaches the wrong protocol handler and is never answered.
    pub(crate) fn ip_protocols(self) -> IpProtocols {
        match self {
            ProbeKind::TcpSyn | ProbeKind::TcpProbe { .. } => {
                IpProtocols::same(IpNextHeaderProtocols::Tcp.0)
            }
            ProbeKind::UdpResolve | ProbeKind::UdpProbe { .. } => {
                IpProtocols::same(IpNextHeaderProtocols::Udp.0)
            }
            ProbeKind::Sctp { .. } => IpProtocols::same(IpNextHeaderProtocols::Sctp.0),
            // The one kind whose two families are different protocols.
            ProbeKind::IcmpEcho { .. } => IpProtocols {
                v4: IpNextHeaderProtocols::Icmp.0,
                v6: IpNextHeaderProtocols::Icmpv6.0,
            },
            // The one kind whose number is the question itself, so the caller
            // chooses it.
            ProbeKind::IpProtocol { number } => IpProtocols::same(number),
        }
    }

    /// The `libpcap`/`tcpdump` filter expression compiled into a kernel BPF program for
    /// the receive half. Only the replies a scan can act on reach userspace.
    fn filter(self) -> String {
        match self {
            // SYN+ACK (open) and RST (closed) both set SYN or RST; nothing else a SYN
            // probe can draw does.
            //
            // Only IPv4 can be narrowed this way. `tcp[tcpflags]` is `proto[x]`
            // indexing, and an IPv6 next-header chain puts the transport header at no
            // fixed offset, so libpcap cannot compile it, and does not say so: written
            // as one unqualified `tcp`, the expression is silently restricted to IPv4
            // and every IPv6 frame is rejected at the EtherType. Prefixing `ip6` fails
            // to compile outright.
            //
            // So the IPv6 half is admitted unnarrowed and the flags are checked in
            // userspace. Every IPv6 TCP segment on every captured interface is copied
            // up; on a host with live IPv6 connections that is real traffic, and it
            // shows in the audit's `off-target` count. It is the only IPv6 receive
            // path there is.
            ProbeKind::TcpSyn => {
                "(ip and tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0) or (ip6 and tcp)"
                    .to_string()
            }
            // Every reply to this kind comes back to the one port the scan sends
            // from, so that is the whole narrowing, and both families get it. What
            // reaches userspace is this scan's own traffic.
            //
            // The flags are checked in userspace: a segment to the right port still
            // has to be one of the two answers a probe can draw, and carry back the
            // value the probe went out with.
            ProbeKind::TcpProbe {
                reply_port,
                icmp_errors,
            } => {
                // Both directions. The outbound half is the scan watching its own
                // probes leave, which tells a port that stayed quiet from one whose
                // probe the OS discarded: macOS does that to raw-socket writes under
                // load and still returns success. It costs one captured frame per
                // probe, all of it this scan's own.
                let tcp = format!("tcp and port {reply_port}");
                // An ICMP error names no ports; the probe it refers to is quoted in
                // its payload, so this half is matched in userspace.
                if icmp_errors {
                    format!("icmp or icmp6 or ({tcp})")
                } else {
                    tcp
                }
            }
            // DNS (53) and mDNS (5353) responses, by source port.
            ProbeKind::UdpResolve => "udp and (src port 53 or src port 5353)".to_string(),
            // A UDP probe draws two kinds of answer. A direct UDP reply comes back
            // to the scan's source port, so it narrows to this scan. An ICMP error
            // carries no ports (the probe is quoted in its payload), so ICMP is
            // matched in userspace.
            ProbeKind::UdpProbe { reply_port } => {
                format!("icmp or icmp6 or (udp and dst port {reply_port})")
            }
            // The ICMP halves of the two filters above, and nothing else. A protocol
            // probe's only possible answer is an ICMP message about it, so every
            // error is admitted and the quotation read in userspace; see
            // [`ProbeKind::IpProtocol`].
            ProbeKind::IpProtocol { .. } => "icmp or icmp6".to_string(),
            // The same shape as the UDP filter, for the same reasons: every answer an
            // INIT can draw comes back to the scan's one port, and an ICMP error
            // carries no ports, so the error half is admitted whole and matched
            // against the quoted probe in userspace.
            ProbeKind::Sctp { reply_port } => {
                format!("icmp or icmp6 or (sctp and dst port {reply_port})")
            }
            // Unnarrowed. The identifier that separates this scan's replies from
            // other pings sits four bytes into the ICMP message, which is `proto[x]`
            // indexing: expressible over IPv4 but not IPv6, whose next-header chain
            // puts the message at no fixed offset. Narrowing only one family would
            // make the two behave differently without any visible reason, so both
            // come up whole and the identifier is matched in userspace.
            //
            // The errors are wanted as well: a host answering an echo with
            // "administratively prohibited" has said something, and it did not come
            // from the host's own stack.
            ProbeKind::IcmpEcho { .. } => "icmp or icmp6".to_string(),
        }
    }
}

/// Why one probe could not be put on the wire.
///
/// Split by whose fact the failure is, since each calls for a different response.
/// [`Unroutable`](Self::Unroutable) and [`Unresolved`](Self::Unresolved) are facts
/// about the destination: it cannot be reached from here, and the sender still works.
/// [`HeldDown`](Self::HeldDown) is one too, while the kernel holds it; asked again
/// after that, the address may answer. [`Unsupported`](Self::Unsupported) is a fact
/// about this transport that holds for the next probe too, so a scan should give up on
/// the path. [`Refused`](Self::Refused) came from this host and may not recur: a full
/// send buffer clears. [`is_unroutable`](Self::is_unroutable) is the test a scan
/// reports by.
///
/// A refusal carries the operating system's own words. "No route to host" and
/// "Permission denied" call for completely different responses from the reader, and
/// no enum could keep pace with what kernels say.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SendError {
    /// This host has no route to that address.
    ///
    /// A fact about the destination, not about this scanner, and the two call for
    /// opposite responses. A send path that does not work is a strategy that did not
    /// run, and the caller must be told the scan covered less than asked. An address
    /// with no route is ordinary: a dual-stack name on an IPv4-only network resolves
    /// to an AAAA nobody here can reach, and calling that a broken scan would make
    /// every such scan look partial.
    ///
    /// Still an error and still reported, as something known about that address.
    #[error("{0}")]
    Unroutable(String),

    /// The neighbour this probe had to be framed to was asked for its hardware address
    /// and did not answer.
    ///
    /// A dead host on the local segment, or a missing gateway. A fact about the
    /// destination like [`Unroutable`](Self::Unroutable), kept separate for a sender
    /// holding a second path. No route on one path is a reason to try another. An
    /// unanswered resolution is an answer about the destination, and a second path
    /// would only ask the same neighbour again, with its own pace and memory deciding
    /// per probe whether it is accepted, queued or refused. See [`SendMode::Auto`] on
    /// macOS.
    #[error("{0}")]
    Unresolved(String),

    /// The kernel will not send to this neighbour because a recent resolution failed,
    /// and will not ask again until its own hold-down has passed.
    ///
    /// macOS returns this, as `EHOSTDOWN`, to every write to an on-link neighbour for
    /// twenty seconds by default after five unanswered requests
    /// (`net.link.ether.inet.host_down_time` and `maxtries`); it asks at most once a
    /// second, and only when a write needs it. The write it gives up on is refused with
    /// `EHOSTUNREACH`, as is every write through a gateway it holds down, so this is
    /// the one refusal that names a hold-down. Linux keeps none: its sockets take every
    /// write to a neighbour it gave up on, and the write restarts resolution.
    ///
    /// A fact about the destination, like [`Unresolved`](Self::Unresolved), but that
    /// one is a resolution this sender asked for and waited out. This one is a kernel
    /// declining to ask, based on a failure it remembers from whoever asked last,
    /// possibly another process, or a moment the neighbour was asleep. Asked after the
    /// hold-down, the question is new.
    #[error("{0}")]
    HeldDown(String),

    /// The host would not send the packet, in its own words.
    #[error("{0}")]
    Refused(String),

    /// This transport cannot express the probe it was handed, and never will.
    #[error("this transport cannot send that probe: {0}")]
    Unsupported(&'static str),

    /// This process, or the system, had no descriptor left to open what the send
    /// needed: a socket, or a link's handle for frames.
    ///
    /// A fact about this machine, like [`Refused`](Self::Refused), but separate because
    /// every layer the open passed through wraps its own words around the one fact a
    /// reader can act on: the file limit.
    #[error("file limit reached")]
    OutOfDescriptors,
}

impl SendError {
    /// Classifies a failure from a lower layer, keeping its whole cause chain.
    ///
    /// Walks `source()`, so a wrapper naming which probe failed does not hide the
    /// operating system's explanation. `thiserror`'s `#[error]` strings already
    /// interpolate their source, so the text is the whole chain.
    ///
    /// Reads the operating system's error kind, since message text differs per
    /// platform and locale. Only the unreachable kinds are singled out; everything
    /// else stays a refusal, including lookalikes: a full send buffer or a permission
    /// failure says nothing about whether the destination exists.
    ///
    /// `EHOSTDOWN` has no [`ErrorKind`](std::io::ErrorKind) of its own and is read by
    /// number, as [`HeldDown`](Self::HeldDown). As a refusal, it would make a scan of
    /// one dead address report itself broken.
    pub(crate) fn from_io<E: std::error::Error + 'static>(error: E) -> Self {
        let chain = || {
            std::iter::successors(Some(&error as &dyn std::error::Error), |cause| {
                cause.source()
            })
            .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        };

        if chain().any(crate::system::descriptors::exhausted) {
            Self::OutOfDescriptors
        } else if chain().any(host_is_down) {
            Self::HeldDown(error.to_string())
        } else if chain().any(|io| {
            matches!(
                io.kind(),
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable
            )
        }) {
            Self::Unroutable(error.to_string())
        } else {
            Self::Refused(error.to_string())
        }
    }

    /// A probe not sent because the routing table gave no answer to the lookup of its
    /// source, in the lookup's own words.
    ///
    /// Always a refusal, never read by [`from_io`](Self::from_io): a failed lookup says
    /// nothing about the destination, and an `EHOSTDOWN` read there would file the host
    /// as one whose neighbour did not answer.
    pub(crate) fn unanswered_route(error: &std::io::Error) -> Self {
        Self::Refused(format!("route lookup failed: {error}"))
    }

    /// Whether this failure is about the destination instead of the sending host: no
    /// route to it, or no answer from the neighbour a route leads through, lately or
    /// just now.
    ///
    /// Separates "the scan could not run" from "that address is not reachable from
    /// here", which are reported differently.
    pub fn is_unroutable(&self) -> bool {
        matches!(
            self,
            Self::Unroutable(_) | Self::Unresolved(_) | Self::HeldDown(_)
        )
    }
}

/// Whether `error` is the kernel's `EHOSTDOWN`: the next hop's address resolution
/// failed lately, and the kernel refuses sends to it for now. See
/// [`SendError::HeldDown`].
pub(crate) fn host_is_down(error: &std::io::Error) -> bool {
    #[cfg(unix)]
    {
        error.raw_os_error() == Some(libc::EHOSTDOWN)
    }
    #[cfg(not(unix))]
    {
        let _ = error;
        false
    }
}

/// What a caller decides about the IP header carrying a probe.
///
/// Addresses, protocol number, lengths and checksums follow from the probe and its
/// destination, so a sender derives them. What is left are the header fields nothing
/// downstream can infer: the hop limit, and on the link-layer path a spoofed source
/// hardware address and fragmentation.
///
/// A struct so further per-probe header choices (IP options, an intentionally wrong
/// checksum) can be added without changing every sender's signature.
///
/// Both backends honour the hop limit: the link-layer sender writes the field in the
/// header it builds, and the raw-socket sender sets it on the socket before the send,
/// under the lock that serialises sends anyway. See
/// `raw::TransportSenderHandle::send_to`.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Emission {
    /// How many hops the probe may cross before a router discards it and reports
    /// having done so.
    pub hop_limit: u8,
    /// The hardware address the frame claims to come from, or `None` for the sending
    /// interface's own. Only a self-built Ethernet frame can carry it, so an emission
    /// with this set cannot go over a raw socket. See
    /// [`requires_link_layer`](Self::requires_link_layer).
    pub source_mac: Option<MacAddr>,
    /// The largest size in bytes of each IP fragment this probe is split into, or
    /// `None` to send it whole. Only a self-built Ethernet frame carries fragments
    /// this engine chose, for either address family. See
    /// [`requires_link_layer`](Self::requires_link_layer).
    pub fragment: Option<u16>,
}

impl Emission {
    /// What an ordinary probe wants: far enough for any path on the public internet.
    /// See [`ip::HOP_LIMIT_ROUTED`](crate::protocols::ip::HOP_LIMIT_ROUTED).
    pub const fn routed() -> Self {
        Self {
            hop_limit: crate::protocols::ip::HOP_LIMIT_ROUTED,
            source_mac: None,
            fragment: None,
        }
    }

    /// A probe built to expire `hops` routers away, so the router that discards it
    /// names itself in the error it sends back.
    ///
    /// This is how a path is measured. A hop limit of zero would be discarded by this
    /// host's own stack, so it is raised to one, the first router.
    pub const fn at_hop(hops: u8) -> Self {
        Self {
            hop_limit: if hops == 0 { 1 } else { hops },
            source_mac: None,
            fragment: None,
        }
    }

    /// The same emission with its hop limit replaced. Carries an evasion profile's
    /// hop limit; path measurement uses [`at_hop`](Self::at_hop).
    #[must_use]
    pub const fn with_hop_limit(mut self, hop_limit: u8) -> Self {
        self.hop_limit = hop_limit;
        self
    }

    /// The same emission sent from a spoofed hardware address. Only a self-built
    /// Ethernet frame can carry it; see
    /// [`requires_link_layer`](Self::requires_link_layer).
    #[must_use]
    pub const fn with_source_mac(mut self, source_mac: MacAddr) -> Self {
        self.source_mac = Some(source_mac);
        self
    }

    /// The same emission split into IP fragments of at most `mtu` bytes. Only a
    /// self-built Ethernet frame can carry the fragments, for either address family;
    /// see [`requires_link_layer`](Self::requires_link_layer).
    #[must_use]
    pub const fn with_fragment(mut self, mtu: u16) -> Self {
        self.fragment = Some(mtu);
        self
    }

    /// Whether this emission can only leave as a self-built Ethernet frame, because it
    /// sets a field a raw socket cannot place: a spoofed source hardware address, or
    /// fragments this engine chose.
    #[must_use]
    pub const fn requires_link_layer(&self) -> bool {
        self.source_mac.is_some() || self.fragment.is_some()
    }
}

impl Default for Emission {
    fn default() -> Self {
        Self::routed()
    }
}

/// Sends an already-built Layer-4 `segment` to `dst`.
///
/// `src` is the source address the segment's checksum was computed against; a
/// raw-socket sender lets the kernel stamp it into the IP header, while a link-layer
/// sender uses it to build the header. `emission` is what the caller decides about
/// that header; see [`Emission`]. Implementations must be safe to share across
/// threads.
pub trait ProbeSender: Send + Sync {
    /// Emits one probe, or says why it did not leave.
    ///
    /// `zone` is the interface a link-local `dst` is valid on, and `None` for every
    /// address that identifies its host on its own. `fe80::1` names a different
    /// machine on every segment, so without a zone it is unreachable.
    ///
    /// [`SendError::Unroutable`] is about `dst`: that address was not covered, while
    /// the sender still works.
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        zone: Option<u32>,
        emission: Emission,
    ) -> Result<(), SendError>;
}

/// The IP protocol number a kind's probes carry, per address family.
///
/// A pair because [`ProbeKind::IcmpEcho`] is two protocols: ICMP is next-header 1 and
/// ICMPv6 is 58. Every other kind names the same protocol twice; see
/// [`same`](Self::same).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpProtocols {
    /// What an IPv4 header carrying this kind's probes says it carries.
    pub v4: u8,
    /// What an IPv6 header carrying this kind's probes says it carries.
    pub v6: u8,
}

impl IpProtocols {
    /// One protocol under both families.
    pub const fn same(protocol: u8) -> Self {
        Self {
            v4: protocol,
            v6: protocol,
        }
    }

    /// The number to stamp into a header addressed to `destination`.
    pub const fn for_destination(self, destination: IpAddr) -> u8 {
        match destination {
            IpAddr::V4(_) => self.v4,
            IpAddr::V6(_) => self.v6,
        }
    }
}

/// Why a probe transport could not be opened.
///
/// Named by the half that failed, since only one has an alternative. A scan that
/// cannot capture cannot hear answers and is over; a scan that cannot open its send
/// socket may still have a link-layer path, which [`SendMode`] selects.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The receive half could not be started.
    #[error("the reply capture could not be started: {0}")]
    Capture(#[from] capture::CaptureError),

    /// The raw send socket could not be opened. Needs root, and on Windows raw TCP
    /// sends are blocked whatever the privileges.
    #[error("the raw send socket could not be opened: {0}")]
    RawSocket(String),

    /// Layer-2 sending was asked for and this host has nothing to send from, holding
    /// only tunnels or loopback. The raw-socket path works here.
    #[error("no Ethernet-capable interface for Layer-2 send: {0}")]
    NoEthernetInterface(String),
}

/// A borrowed Layer-4 segment presented as a `pnet` packet, so raw bytes can be handed
/// straight to a `TransportSender` without a copy. The whole slice is the packet; it
/// has no separate payload as far as the transport is concerned.
struct RawSegment<'a>(&'a [u8]);

impl Packet for RawSegment<'_> {
    fn packet(&self) -> &[u8] {
        self.0
    }
    fn payload(&self) -> &[u8] {
        &[]
    }
}

/// The default sender: emits segments over a raw Layer-4 socket and lets the kernel
/// route them. Works on Linux and macOS for on-link and off-link destinations, with no
/// ARP/NDP or gateway bookkeeping of its own.
pub struct RawIpSender {
    handle: TransportSenderHandle,
}

impl RawIpSender {
    fn open(kind: ProbeKind) -> Result<Self, TransportError> {
        raw::open_sender(kind.transport_type())
            .map(|handle| Self { handle })
            .map_err(|e| TransportError::RawSocket(format!("{e:#}")))
    }
}

impl ProbeSender for RawIpSender {
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        zone: Option<u32>,
        emission: Emission,
    ) -> Result<(), SendError> {
        // The kernel builds the IP header and the frame here, so a field only a
        // self-built frame can carry, such as a spoofed hardware address, cannot be
        // honoured. Refused with the reason, so a scan that reports a spoof did one.
        if emission.requires_link_layer() {
            return Err(SendError::Unsupported(
                "this emission sets a field only a self-built Ethernet frame can carry",
            ));
        }
        self.handle
            .send_from(RawSegment(segment), src, dst, zone, emission.hop_limit)
            .map(|_| ())
            .map_err(SendError::from_io)
    }
}

/// Builds its own Ethernet frames, and falls back to the raw socket for destinations
/// [`EthernetSender`] cannot frame: on-link IPv6 (no NDP) and tunnels. Loopback it
/// frames, to the loopback interface.
///
/// The macOS default. There the raw socket accepts a large scan's sends and drops a
/// quarter of them before the wire, where a self-built frame goes out.
///
/// Two failures are final. An emission only a frame can carry would leave the socket
/// as a different probe from the one asked for. And a neighbour that did not answer
/// its address resolution ([`SendError::Unresolved`]) was reachable by a frame and
/// asked: the socket would hand the kernel the same question, which it answers in its
/// own time. macOS takes the first few writes while it asks and discards them, then
/// refuses the rest for twenty seconds once it gives up, so each port's verdict would
/// depend on where the kernel was in that cycle. Refusing here treats every probe to
/// the address alike, and the scan reads one absent host.
///
/// Generic over its two senders so the rule is tested on this type; the transport
/// only builds the one pairing.
struct LinkLayerFirst<L = EthernetSender, S = RawIpSender> {
    link: L,
    /// [`None`] when this process may inject frames but not open a raw socket: an
    /// unprivileged run on macOS with the BPF devices given to a group. Only the
    /// fallback goes missing: anything with Ethernet in front of it, and loopback, is
    /// still reached by frame; only tunnel-only addresses and IPv6 neighbours needed
    /// the socket.
    socket: Option<S>,
}

impl<L: ProbeSender, S: ProbeSender> ProbeSender for LinkLayerFirst<L, S> {
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        zone: Option<u32>,
        emission: Emission,
    ) -> Result<(), SendError> {
        let framed = self.link.send(segment, src, dst, zone, emission);
        let final_answer = match &framed {
            Ok(()) | Err(SendError::Unresolved(_)) => true,
            Err(_) => emission.requires_link_layer(),
        };
        if final_answer {
            return framed;
        }
        match &self.socket {
            Some(socket) => socket.send(segment, src, dst, zone, emission),
            // The frame's own error, since it is why this destination went
            // unreached.
            None => framed,
        }
    }
}

/// A sender that refuses to send. Paired with a capture for receive-only transports
/// (the DNS/mDNS resolver only listens), so no raw send socket is opened needlessly,
/// and a stray send fails loudly.
struct NoopSender;

impl ProbeSender for NoopSender {
    fn send(
        &self,
        _segment: &[u8],
        _src: IpAddr,
        _dst: IpAddr,
        _zone: Option<u32>,
        _emission: Emission,
    ) -> Result<(), SendError> {
        Err(SendError::Unsupported("it is receive-only"))
    }
}

/// A probe transport: a swappable sender paired with a capture-fed receive stream.
/// Scanners hold one of these and depend only on [`ProbeTransport::tx`] and
/// [`ProbeTransport::rx`].
#[non_exhaustive]
pub struct ProbeTransport {
    /// The send half, boxed so the backend can vary without touching callers.
    pub tx: Box<dyn ProbeSender>,
    /// Parsed replies ([`capture::CapturedSegment`]), merged across every captured
    /// interface.
    pub rx: CaptureStream,
    /// Keeps the capture threads alive for this transport's lifetime, and holds the
    /// counters they publish.
    capture: CaptureGuard,
    /// Where the send half's address resolution stands, for a scan that holds a host's
    /// probes while its neighbour is resolved. See [`NeighborWatch`]. `None` where an
    /// unanswering neighbour is refused at the send with nothing to read beforehand: a
    /// raw socket on macOS.
    ///
    /// Boxed so the watch's locks sit behind a pointer; the transport's auto traits are
    /// public and would otherwise carry them.
    neighbors: Option<Box<NeighborWatch>>,
    /// The kind this transport was opened for, which decides what its capture admits
    /// and so what a scan over it can hear. `None` for one built from parts, whose
    /// receive stream carries whatever is pushed onto it. See
    /// [`reply_port`](Self::reply_port) and [`mismatched_for`](Self::mismatched_for).
    kind: Option<ProbeKind>,
}

/// Where the address resolution a transport's sends depend on stands, read by a scan
/// before it hands a probe over.
///
/// Two kinds, because who resolves a neighbour decides what a scan can see of it and
/// when resolution starts.
pub(crate) enum NeighborWatch {
    /// The kernel's own resolution, behind a raw socket on Linux. A write to a
    /// neighbour starts it, and the kernel tells the socket nothing of how it went;
    /// its table does. See [`KernelNeighbors`].
    Kernel(KernelNeighbors),
    /// A frame sender's own resolution. Asking where it stands starts it, and a send
    /// to a neighbour still being resolved waits for it. See [`LinkNeighbors`].
    Frames(LinkNeighbors),
}

impl ProbeTransport {
    /// What the receive path's kernel buffers have done so far, summed over every
    /// interface this transport captures on.
    ///
    /// The scanner knows how many replies it saw; only this knows how many arrived and
    /// were discarded before it could read them, so a scanner reports both. `None` for
    /// a transport with no capture behind it.
    pub fn capture_counts(&self) -> Option<CaptureCounts> {
        self.capture.counts()
    }

    /// Where the address resolution this transport's sends wait on stands. See
    /// [`NeighborWatch`].
    pub(crate) fn neighbors(&self) -> Option<&NeighborWatch> {
        self.neighbors.as_deref()
    }

    /// The port this transport's capture admits replies to, where the kind it was
    /// opened for fixes one: [`ProbeKind::TcpProbe`], [`ProbeKind::UdpProbe`] and
    /// [`ProbeKind::Sctp`]. `None` for a kind that fixes none, and for a transport
    /// built from parts.
    ///
    /// A scan over this transport sends from this port, whatever port it was handed
    /// beside it: answers come back to the port their probes left from, and the
    /// capture filters out answers to any other. So the port lives here, with the
    /// capture that filters on it.
    pub fn reply_port(&self) -> Option<u16> {
        self.kind.and_then(ProbeKind::reply_port)
    }

    /// The kind this transport was opened for, where its capture filters on one, if
    /// that kind cannot carry a port scan of `protocol`.
    ///
    /// A transport built from parts filters nothing, so it carries anything.
    pub(crate) fn mismatched_for(&self, protocol: Protocol) -> Option<ProbeKind> {
        self.kind.filter(|kind| !kind.carries_port_scan(protocol))
    }

    /// This transport, standing in for one opened for `kind`.
    #[cfg(test)]
    pub(crate) fn opened_for(mut self, kind: ProbeKind) -> Self {
        self.kind = Some(kind);
        self
    }

    /// This transport, reading `neighbors` as the kernel's neighbour table.
    #[cfg(test)]
    pub(crate) fn with_kernel_neighbors(mut self, neighbors: KernelNeighbors) -> Self {
        self.neighbors = Some(Box::new(NeighborWatch::Kernel(neighbors)));
        self
    }

    /// This transport, reading `neighbors` as its frame sender's resolutions.
    #[cfg(test)]
    pub(crate) fn with_link_neighbors(mut self, neighbors: LinkNeighbors) -> Self {
        self.neighbors = Some(Box::new(NeighborWatch::Frames(neighbors)));
        self
    }
    /// Opens a transport for `kind` with the platform-default send backend
    /// ([`SendMode::Auto`]).
    pub fn open(kind: ProbeKind) -> Result<Self, TransportError> {
        Self::open_with(kind, SendMode::Auto)
    }

    /// Opens a transport for `kind`, choosing the send backend per `mode`.
    ///
    /// Every mode pairs with a filtered `libpcap` capture on every interface that is
    /// up, loopback included, so a reply is caught whichever interface the kernel
    /// routed the probe out of. The egress path can differ per destination,
    /// especially under a VPN.
    pub fn open_with(kind: ProbeKind, mode: SendMode) -> Result<Self, TransportError> {
        Self::open_capturing(kind, mode, &capturable_interfaces())
    }

    /// [`open_with`](Self::open_with), capturing on `links` alone.
    ///
    /// For a scan that knows where its targets are. Each capture holds a system
    /// device, on macOS one of a fixed number of BPF devices shared by every process,
    /// and a capture on a link no reply can arrive by wastes one. See
    /// [`capture_links_toward`].
    pub(crate) fn open_capturing(
        kind: ProbeKind,
        mode: SendMode,
        links: &[Zone],
    ) -> Result<Self, TransportError> {
        match mode {
            SendMode::Ethernet => Self::open_ethernet_capturing(kind, links),
            SendMode::RawSocket => Self::open_on(kind, links),
            // Windows blocks raw-socket TCP sends; macOS accepts them and silently
            // drops a quarter. Elsewhere the raw socket reaches everything without
            // ARP. See [`LinkLayerFirst`].
            SendMode::Auto => {
                #[cfg(windows)]
                {
                    Self::open_ethernet_capturing(kind, links)
                }
                #[cfg(target_os = "macos")]
                {
                    Self::open_link_first_capturing(kind, links)
                }
                #[cfg(not(any(windows, target_os = "macos")))]
                {
                    Self::open_on(kind, links)
                }
            }
        }
    }

    /// [`open`](Self::open) against an explicit list of links.
    pub fn open_on(kind: ProbeKind, links: &[Zone]) -> Result<Self, TransportError> {
        let (rx, capture) = capture::segments(
            links,
            &CaptureOptions::for_replies(kind.filter()),
            REPLY_QUEUE_DEPTH,
        )?;
        let tx: Box<dyn ProbeSender> = Box::new(RawIpSender::open(kind)?);
        Ok(Self {
            tx,
            rx,
            capture,
            neighbors: KernelNeighbors::from_system()
                .map(|table| Box::new(NeighborWatch::Kernel(table))),
            kind: Some(kind),
        })
    }

    /// A `LinkLayerFirst` transport: frames what it can, raw socket for the rest. The
    /// macOS default. A host with no Ethernet interface gets the plain raw-socket
    /// transport.
    pub fn open_link_first(kind: ProbeKind) -> Result<Self, TransportError> {
        Self::open_link_first_capturing(kind, &capturable_interfaces())
    }

    /// [`open_link_first`](Self::open_link_first), capturing on `links` alone.
    fn open_link_first_capturing(kind: ProbeKind, links: &[Zone]) -> Result<Self, TransportError> {
        let Some(link) = EthernetSender::from_system(kind.ip_protocols()) else {
            return Self::open_on(kind, links);
        };
        let (rx, capture) = capture::segments(
            links,
            &CaptureOptions::for_replies(kind.filter()),
            REPLY_QUEUE_DEPTH,
        )?;
        let neighbors = Some(Box::new(NeighborWatch::Frames(link.neighbors())));
        Ok(Self {
            tx: Box::new(LinkLayerFirst {
                link,
                // Not `?`: a process that may inject frames but not open a raw socket
                // still scans everything with Ethernet in front of it; failing here
                // would fall back to connect scanning with the link-layer path unused.
                socket: RawIpSender::open(kind).ok(),
            }),
            rx,
            capture,
            neighbors,
            kind: Some(kind),
        })
    }

    /// Opens a transport whose send half builds and emits Ethernet frames directly
    /// (`EthernetSender`).
    ///
    /// For Windows (where raw TCP sends are blocked) and for bypassing the host stack.
    /// Fails if the host has no Ethernet-capable interface, only tunnels or loopback;
    /// then use [`open`](Self::open).
    pub fn open_ethernet(kind: ProbeKind) -> Result<Self, TransportError> {
        Self::open_ethernet_capturing(kind, &capturable_interfaces())
    }

    /// [`open_ethernet`](Self::open_ethernet), capturing on `links` alone.
    pub(crate) fn open_ethernet_capturing(
        kind: ProbeKind,
        links: &[Zone],
    ) -> Result<Self, TransportError> {
        let sender = EthernetSender::from_system(kind.ip_protocols()).ok_or_else(|| {
            TransportError::NoEthernetInterface(
                "the host has only tunnel or loopback interfaces".to_string(),
            )
        })?;
        let (rx, capture) = capture::segments(
            links,
            &CaptureOptions::for_replies(kind.filter()),
            REPLY_QUEUE_DEPTH,
        )?;
        let neighbors = Some(Box::new(NeighborWatch::Frames(sender.neighbors())));
        Ok(Self {
            tx: Box::new(sender),
            rx,
            capture,
            neighbors,
            kind: Some(kind),
        })
    }

    /// Opens a receive-only transport: a filtered capture on every up interface, with
    /// a sender that refuses to send.
    ///
    /// For consumers that only listen, such as the passive DNS/mDNS resolver. No raw
    /// send socket is opened, so a host that blocks raw sockets can still resolve
    /// hostnames.
    pub fn open_receiver(kind: ProbeKind) -> Result<Self, TransportError> {
        Self::open_receiver_capturing(kind, &capturable_interfaces())
    }

    /// [`open_receiver`](Self::open_receiver), capturing on `links` alone.
    pub(crate) fn open_receiver_capturing(
        kind: ProbeKind,
        links: &[Zone],
    ) -> Result<Self, TransportError> {
        let (rx, capture) = capture::segments(
            links,
            &CaptureOptions::for_replies(kind.filter()),
            REPLY_QUEUE_DEPTH,
        )?;
        Ok(Self {
            tx: Box::new(NoopSender),
            rx,
            capture,
            neighbors: None,
            kind: Some(kind),
        })
    }

    /// Builds a transport from an explicit sender and receive stream, opening no
    /// socket and no capture.
    ///
    /// Lets a test run a scanner against a synthetic network: `tx` observes the probes
    /// the scanner emits, and whatever is pushed onto the sending half of `rx` arrives
    /// as though captured off the wire. With no capture threads, the transport holds an
    /// inert [`CaptureGuard`].
    ///
    /// Requires the `test-support` feature outside this crate.
    #[cfg(any(test, feature = "test-support"))]
    pub fn from_parts(tx: Box<dyn ProbeSender>, rx: CaptureStream) -> Self {
        Self {
            tx,
            rx,
            capture: CaptureGuard::noop(),
            neighbors: None,
            kind: None,
        }
    }

    /// [`from_parts`](Self::from_parts) with a capture already stopped, for testing
    /// what a scanner makes of a receive path that went deaf.
    #[cfg(test)]
    pub(crate) fn from_parts_deaf(tx: Box<dyn ProbeSender>, rx: CaptureStream) -> Self {
        Self {
            tx,
            rx,
            capture: CaptureGuard::stopped_early(),
            neighbors: None,
            kind: None,
        }
    }
}

/// The interfaces a capture should listen on: every interface that is up, and
/// loopback whether or not it reports being up.
///
/// [`is_up`](crate::system::interface::Link::is_up) wants a carrier as well as the
/// administrative flag, and loopback has no carrier: Linux leaves its operational
/// state `unknown` for the life of the machine. That is the right test for what to
/// probe out of, but here, deciding what to listen on, it would drop `lo`, and every
/// localhost probe would go out with none heard back.
///
/// Each is named as a [`Zone`], carrying the index with the name. The interface table
/// was already read, and a finding scoped to a link needs the index, since a
/// link-local address names a different machine on every link.
pub(crate) fn capturable_interfaces() -> Vec<Zone> {
    capturable(&crate::system::interface::interfaces_or_none())
}

/// [`capturable_interfaces`] among `links`.
fn capturable(links: &[Link]) -> Vec<Zone> {
    links
        .iter()
        .filter(|link| link.is_up() || link.is_loopback())
        .map(Link::zone)
        .collect()
}

/// The links a reply to a probe of `targets` can arrive by, sent from `forced` where
/// the scan pins its source: what a scan that knows its targets captures on.
///
/// A reply comes back to the address its probe was sent from, so it arrives by the
/// link holding that address. For a target on one of this host's segments, that is
/// the segment's link; for a routed one, the link holding the source the routing table
/// picks, which is the tunnel's own link under a VPN; for this host's own addresses
/// and loopback's, loopback. A pinned source is checked against both the pin and the
/// routing table, since the probe may leave by the route while its answer comes back
/// to the pin.
///
/// Every link that is up where routing cannot say: an address with no route, or a
/// source no link holds. An extra capture costs a device, a missing one loses the
/// reply, so doubt resolves toward listening. Likewise for a plan with more addresses
/// than [`MAX_ENUMERABLE_ADDRESSES`]: its phases route each one anyway, and routing
/// them again here would double the one planning cost that grows with the plan.
///
/// [`MAX_ENUMERABLE_ADDRESSES`]: crate::system::interface::MAX_ENUMERABLE_ADDRESSES
///
/// Worth narrowing because each capture holds a system device: on macOS one of a fixed
/// pool of BPF devices shared by every process, which a few scans capturing on every
/// link of a machine with dozens of links exhaust.
pub(crate) fn capture_links_toward(targets: &IpSet, forced: &[IpAddr]) -> Vec<Zone> {
    use crate::system::interface::{
        MAX_ENUMERABLE_ADDRESSES, is_enumerable, map_ips_to_interfaces,
        map_ips_to_interfaces_forced,
    };

    let links = crate::system::interface::interfaces_or_none();
    // What the routing below would walk address by address: every IPv4 range, and
    // the IPv6 ones small enough to walk.
    let mut routed_one_by_one = IpSet::new();
    for range in targets.v4() {
        routed_one_by_one.push_v4_range(*range);
    }
    for range in targets.v6().iter().filter(|range| is_enumerable(range)) {
        routed_one_by_one.push_v6_range(*range);
    }
    if routed_one_by_one.len_gross() > MAX_ENUMERABLE_ADDRESSES {
        return capturable(&links);
    }
    let mut routings = vec![map_ips_to_interfaces(targets.clone())];
    if !forced.is_empty() {
        routings.push(map_ips_to_interfaces_forced(targets.clone(), forced));
    }
    links_replies_reach(&links, &routings).unwrap_or_else(|| capturable(&links))
}

/// The links among `links` a reply to what `routings` planned arrives by, or `None`
/// where one cannot be named; see [`capture_links_toward`].
fn links_replies_reach(links: &[Link], routings: &[RoutedTargets]) -> Option<Vec<Zone>> {
    let loopback: Vec<&Link> = links.iter().filter(|link| link.is_loopback()).collect();
    let mut reached: Vec<Zone> = Vec::new();
    for routing in routings {
        reached.extend(routing.local.keys().map(Link::zone));
        for routed in &routing.routed {
            let holder = links.iter().find(|link| {
                link.addresses()
                    .iter()
                    .any(|held| held.address() == routed.source)
            })?;
            reached.push(holder.zone());
        }
        let unmapped_is_loopback =
            routing
                .unmapped
                .v4()
                .iter()
                .all(|range| range.start_addr().is_loopback() && range.end_addr().is_loopback())
                && routing.unmapped.v6().iter().all(|range| {
                    range.start_addr().is_loopback() && range.end_addr().is_loopback()
                });
        if !unmapped_is_loopback {
            return None;
        }
        if !routing.ours.is_empty() || !routing.unmapped.is_empty() {
            if loopback.is_empty() {
                return None;
            }
            reached.extend(loopback.iter().map(|link| link.zone()));
        }
    }
    reached.sort_by(|one, other| one.name().cmp(other.name()));
    reached.dedup();
    (!reached.is_empty()).then_some(reached)
}

/// A record of one recorded send: `(segment, source, destination)`.
#[cfg(test)]
pub type SentProbe = (Vec<u8>, IpAddr, IpAddr);

/// A [`ProbeSender`] that records what it was asked to send, so transport wiring and
/// scanner logic can be tested without root. Available crate-wide under `cfg(test)`.
#[cfg(test)]
#[derive(Clone, Default)]
pub struct MockSender {
    /// Every probe handed to [`send`](ProbeSender::send), oldest first. Shared, so a
    /// clone of the sender given to a scanner reads the same list.
    pub sent: std::sync::Arc<std::sync::Mutex<Vec<SentProbe>>>,
}

#[cfg(test)]
impl ProbeSender for MockSender {
    fn send(
        &self,
        segment: &[u8],
        src: IpAddr,
        dst: IpAddr,
        _zone: Option<u32>,
        _emission: Emission,
    ) -> Result<(), SendError> {
        self.sent.lock().unwrap().push((segment.to_vec(), src, dst));
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
    use crate::system::interface::LinkKind;

    /// A link named `name` holding `address`, of `kind`.
    fn holding(name: &str, index: u32, kind: LinkKind, address: &str) -> Link {
        use crate::system::interface::LinkAddress;
        let address: IpAddr = address.parse().expect("an address");
        Link::new(name, index)
            .with_kind(kind)
            .with_addresses(vec![LinkAddress::new(address, 24)])
    }

    /// Loopback, a wired segment, a VPN's tunnel, and a link no target is on.
    fn machine() -> Vec<Link> {
        vec![
            holding("lo0", 1, LinkKind::Loopback, "127.0.0.1"),
            holding("en0", 4, LinkKind::Wired, "192.0.2.10"),
            holding("utun4", 20, LinkKind::Virtual, "198.51.100.2"),
            holding("awdl0", 11, LinkKind::Wireless, "203.0.113.77"),
        ]
    }

    /// Each port scan is carried by the kinds whose capture admits its answers and no
    /// other, and a transport built from parts, which filters nothing, carries every
    /// one.
    ///
    /// The UDP resolver's kind is the near miss: the same protocol, but a capture that
    /// admits only name-service replies, so a UDP port scan over it would hear nothing.
    #[test]
    fn a_transport_carries_the_port_scans_its_capture_admits_answers_to() {
        use Protocol::{Sctp, Tcp, Udp};
        let tcp = ProbeKind::TcpProbe {
            reply_port: 40_000,
            icmp_errors: true,
        };
        let udp = ProbeKind::UdpProbe { reply_port: 40_000 };
        let sctp = ProbeKind::Sctp { reply_port: 40_000 };
        for (kind, carried) in [
            (ProbeKind::TcpSyn, &[Tcp][..]),
            (tcp, &[Tcp]),
            (udp, &[Udp]),
            (sctp, &[Sctp]),
            (ProbeKind::UdpResolve, &[]),
            (ProbeKind::IcmpEcho { identifier: 7 }, &[]),
            (ProbeKind::IpProtocol { number: 47 }, &[]),
        ] {
            for protocol in [Tcp, Udp, Sctp] {
                assert_eq!(
                    kind.carries_port_scan(protocol),
                    carried.contains(&protocol),
                    "{kind:?} for {protocol:?}"
                );
            }
        }

        let (_tx, rx) = tokio::sync::mpsc::channel(1);
        let parts = ProbeTransport::from_parts(Box::new(MockSender::default()), rx);
        assert!(
            [Tcp, Udp, Sctp]
                .iter()
                .all(|p| parts.mismatched_for(*p).is_none())
        );
        let opened = parts.opened_for(udp);
        assert_eq!(opened.reply_port(), Some(40_000));
        assert!(opened.mismatched_for(Tcp).is_some());
    }

    fn names(zones: Option<Vec<Zone>>) -> Option<Vec<String>> {
        zones.map(|zones| zones.iter().map(|zone| zone.name().to_owned()).collect())
    }

    /// **A scan captures only on the links a reply to it can arrive by.**
    ///
    /// Every capture holds a device, and on macOS the devices are a fixed pool shared
    /// by every process. A reply comes back to its probe's source: on the segment of an
    /// on-link target, on the link holding a routed target's source (the tunnel's,
    /// under a VPN), and over loopback for this host's own addresses.
    #[test]
    fn a_capture_listens_where_replies_to_its_targets_arrive() {
        let links = machine();
        let on = |routing: RoutedTargets| names(links_replies_reach(&links, &[routing]));

        let loopback = RoutedTargets {
            unmapped: "127.0.0.1".parse().expect("an address"),
            ..RoutedTargets::default()
        };
        assert_eq!(on(loopback), Some(vec!["lo0".to_owned()]));

        let mut local = std::collections::HashMap::new();
        local.insert(links[1].clone(), "192.0.2.0/24".parse().expect("a range"));
        let beside_a_vpn = RoutedTargets {
            local,
            routed: vec![crate::system::interface::RoutedTarget {
                target: "203.0.113.5".parse().expect("an address"),
                source: "198.51.100.2".parse().expect("an address"),
            }],
            ..RoutedTargets::default()
        };
        assert_eq!(
            on(beside_a_vpn),
            Some(vec!["en0".to_owned(), "utun4".to_owned()])
        );

        let ours = RoutedTargets {
            ours: "192.0.2.10".parse().expect("an address"),
            ..RoutedTargets::default()
        };
        assert_eq!(on(ours), Some(vec!["lo0".to_owned()]), "this host's own");
    }

    /// Where routing cannot name the link a reply arrives by, a capture listens on
    /// every link, since missing that link loses the reply and an extra costs only a
    /// device.
    #[test]
    fn a_capture_whose_replies_the_routing_cannot_place_listens_everywhere() {
        let links = machine();
        let no_route = RoutedTargets {
            unmapped: "203.0.113.9".parse().expect("an address"),
            ..RoutedTargets::default()
        };
        assert_eq!(links_replies_reach(&links, &[no_route]), None);

        let unheld_source = RoutedTargets {
            routed: vec![crate::system::interface::RoutedTarget {
                target: "203.0.113.5".parse().expect("an address"),
                source: "198.51.100.99".parse().expect("an address"),
            }],
            ..RoutedTargets::default()
        };
        assert_eq!(links_replies_reach(&links, &[unheld_source]), None);
    }

    /// A raw socket reaches whatever the kernel carries and a frame what has Ethernet
    /// in front of it, on every platform. What `Auto` reaches depends on the platform
    /// and, on macOS, on the process, so there it is checked against the process's own
    /// answer.
    #[test]
    fn a_socket_reaches_past_frames_and_a_frame_does_not() {
        assert!(SendMode::RawSocket.reaches_past_frames());
        assert!(!SendMode::Ethernet.reaches_past_frames());

        #[cfg(target_os = "macos")]
        assert_eq!(
            SendMode::Auto.reaches_past_frames(),
            crate::system::privilege::can_send_raw(),
            "frames first, and the socket behind them only for a process that may open one"
        );
        #[cfg(windows)]
        assert!(!SendMode::Auto.reaches_past_frames(), "frames alone");
        #[cfg(not(any(windows, target_os = "macos")))]
        assert!(SendMode::Auto.reaches_past_frames(), "the socket alone");
    }

    #[tokio::test]
    async fn transport_forwards_sends_and_delivers_replies() {
        use crate::transport::capture::CapturedSegment;
        use std::net::Ipv4Addr;

        let mock = MockSender::default();
        let recorded = mock.sent.clone();
        let (reply_tx, reply_rx) = tokio::sync::mpsc::channel(1024);
        let mut transport = ProbeTransport::from_parts(Box::new(mock), reply_rx);

        let src = IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2));
        let dst = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        transport
            .tx
            .send(&[0xAA, 0xBB], src, dst, None, Emission::routed())
            .unwrap();

        let sent = recorded.lock().unwrap().clone();
        assert_eq!(sent, vec![(vec![0xAA, 0xBB], src, dst)]);

        // A reply pushed onto the capture stream arrives on rx unchanged.
        let reply = CapturedSegment::synthetic(
            dst,
            pnet_packet::ip::IpNextHeaderProtocols::Udp.0,
            vec![1, 2, 3],
        );
        reply_tx.send(reply.clone()).await.unwrap();
        assert_eq!(transport.rx.recv().await, Some(reply));
    }

    /// The fallback keeps the macOS default from losing reach. The frame path cannot
    /// resolve an on-link IPv6 neighbour and has no route to loopback or into a
    /// tunnel, and those destinations must keep working.
    #[test]
    fn a_destination_the_frame_path_cannot_reach_goes_through_the_socket() {
        for cannot in [
            SendError::Unsupported("no NDP here"),
            SendError::Unroutable("no Ethernet route from 198.51.100.1".to_string()),
        ] {
            let socket = MockSender::default();
            let sent = socket.sent.clone();
            let sender = LinkLayerFirst {
                link: RefusingSender(cannot),
                socket: Some(socket),
            };

            let result = send_one(&sender, Emission::routed());

            assert!(result.is_ok(), "the socket served it: {result:?}");
            assert_eq!(sent.lock().unwrap().len(), 1);
        }
    }

    /// A probe carrying a field only a self-built frame can express is not retried
    /// through the socket, which would send a different probe and report it as the
    /// one asked for.
    #[test]
    fn a_probe_only_a_frame_can_carry_is_never_retried_through_the_socket() {
        let socket = MockSender::default();
        let sent = socket.sent.clone();
        let sender = LinkLayerFirst {
            link: RefusingSender(SendError::Refused("the link went down".to_string())),
            socket: Some(socket),
        };

        let spoofed = Emission {
            source_mac: Some(crate::model::mac::MacAddr::new(2, 0, 0, 0, 0, 1)),
            ..Emission::routed()
        };
        assert!(spoofed.requires_link_layer(), "test premise");

        let result = send_one(&sender, spoofed);

        assert!(result.is_err(), "the refusal stands");
        assert!(
            sent.lock().unwrap().is_empty(),
            "and nothing went out the other way"
        );
    }

    /// A neighbour the frame path asked and heard nothing from is not asked again
    /// through the kernel. The kernel would ask the same neighbour and accept or refuse
    /// each probe depending on its progress, so one dead address's ports would come
    /// back part silent and part unasked. The frame's answer stands, as a fact about
    /// the destination.
    #[test]
    fn a_neighbour_that_did_not_answer_is_not_asked_again_through_the_socket() {
        let socket = MockSender::default();
        let sent = socket.sent.clone();
        let sender = LinkLayerFirst {
            link: RefusingSender(SendError::Unresolved(
                "198.51.100.9 did not answer address resolution on en0".to_string(),
            )),
            socket: Some(socket),
        };

        let result = send_one(&sender, Emission::routed());

        assert!(
            matches!(result, Err(SendError::Unresolved(_))),
            "the frame's answer is the one reported: {result:?}"
        );
        assert!(
            result.as_ref().is_err_and(SendError::is_unroutable),
            "and it is read as the destination's, not this host's"
        );
        assert!(
            sent.lock().unwrap().is_empty(),
            "nothing was handed to the kernel"
        );
    }

    /// A sender that always fails the same way, for exercising the fallback.
    struct RefusingSender(SendError);

    impl ProbeSender for RefusingSender {
        fn send(
            &self,
            _segment: &[u8],
            _src: IpAddr,
            _dst: IpAddr,
            _zone: Option<u32>,
            _emission: Emission,
        ) -> Result<(), SendError> {
            Err(match &self.0 {
                SendError::Unsupported(why) => SendError::Unsupported(why),
                SendError::Refused(why) => SendError::Refused(why.clone()),
                SendError::Unroutable(why) => SendError::Unroutable(why.clone()),
                SendError::Unresolved(why) => SendError::Unresolved(why.clone()),
                SendError::HeldDown(why) => SendError::HeldDown(why.clone()),
                SendError::OutOfDescriptors => SendError::OutOfDescriptors,
            })
        }
    }

    /// One probe through `sender`, to an address the tests share.
    fn send_one(sender: &dyn ProbeSender, emission: Emission) -> Result<(), SendError> {
        let src = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 1));
        let dst = IpAddr::V4(std::net::Ipv4Addr::new(198, 51, 100, 9));
        sender.send(&[0xAA], src, dst, None, emission)
    }

    /// A Layer-2 sender writes the IP header itself and reads the protocol number only
    /// from this. A UDP probe announced as TCP is invisible locally; the target's stack
    /// hands it to the wrong protocol handler and it is never answered.
    #[test]
    fn every_probe_kind_carries_its_own_ip_protocol() {
        assert_eq!(
            ProbeKind::TcpSyn.ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Tcp.0)
        );
        assert_eq!(
            ProbeKind::TcpProbe {
                reply_port: 50_000,
                icmp_errors: true,
            }
            .ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Tcp.0)
        );
        assert_eq!(
            ProbeKind::UdpResolve.ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Udp.0)
        );
        assert_eq!(
            ProbeKind::UdpProbe { reply_port: 40_000 }.ip_protocols(),
            IpProtocols::same(IpNextHeaderProtocols::Udp.0)
        );
    }

    /// ICMP is the one kind whose families are different protocols, so the destination
    /// chooses the number.
    ///
    /// Getting it wrong is silent: an ICMPv6 message announced as protocol 1 goes to a
    /// handler that will not recognise it, the probe goes unanswered, and a scan wrongly
    /// concludes the host did not reply.
    #[test]
    fn an_icmp_probe_names_a_different_protocol_per_family() {
        let protocols = ProbeKind::IcmpEcho { identifier: 1 }.ip_protocols();
        assert_eq!(protocols.v4, IpNextHeaderProtocols::Icmp.0);
        assert_eq!(protocols.v6, IpNextHeaderProtocols::Icmpv6.0);
        assert_eq!(
            protocols.for_destination(IpAddr::from([192, 0, 2, 1])),
            IpNextHeaderProtocols::Icmp.0
        );
        assert_eq!(
            protocols.for_destination("2001:db8::1".parse().unwrap()),
            IpNextHeaderProtocols::Icmpv6.0
        );
    }

    /// The ICMP filter admits both families whole.
    ///
    /// The echo identifier cannot be expressed in the filter, since it sits past a
    /// header of variable length over IPv6. Narrowing only the IPv4 half would make
    /// the two families behave differently without any visible reason.
    #[test]
    fn the_icmp_filter_admits_both_families() {
        assert_eq!(
            ProbeKind::IcmpEcho { identifier: 4242 }.filter(),
            "icmp or icmp6"
        );
    }

    /// The UDP filter must narrow direct replies to the scan's own source port, and
    /// leave ICMP unnarrowed, since an ICMP error carries no port to match.
    #[test]
    fn udp_probe_filter_narrows_replies_to_the_scan_source_port() {
        let filter = ProbeKind::UdpProbe { reply_port: 54_321 }.filter();
        assert_eq!(filter, "icmp or icmp6 or (udp and dst port 54321)");
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Filter conformance
// ══════════════════════════════════════════════════════════════════════════════

/// What each [`ProbeKind`]'s filter admits, judged by `libpcap` itself.
///
/// The only tests in the crate that exercise the receive path's real gatekeeper. Every
/// scanner test drives a synthetic transport through [`ProbeTransport::from_parts`],
/// which compiles no filter, so a scanner test can pass against a simulated network
/// while the same scan on a real one sees nothing. The only check is to compile the
/// expression and put a frame through it.
///
/// The evaluation is `libpcap`'s `pcap_offline_filter` running the compiled program,
/// the same program the kernel gets, over a frame built by this crate's packet
/// builders. Nothing here reimplements a filter or a parser, since an instrument
/// sharing the code's assumptions would confirm them.
#[cfg(test)]
mod filter_conformance {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use crate::model::mac::MacAddr;
    use pnet_packet::icmpv6::{Icmpv6Code, Icmpv6Types, MutableIcmpv6Packet};
    use pnet_packet::ip::IpNextHeaderProtocols;
    use pnet_packet::tcp::MutableTcpPacket;

    use super::ProbeKind;
    use crate::protocols::udp;
    use crate::transport::frame::{FrameSpec, build_ethernet_frame};

    const SRC_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));
    const DST_V4: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 20));
    const SRC_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x10));
    const DST_V6: IpAddr = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x20));

    const SYN: u8 = 1 << 1;
    const RST: u8 = 1 << 2;
    const ACK: u8 = 1 << 4;

    const TCP_HDR_LEN: usize = 20;
    const ICMPV6_UNUSED_LEN: usize = 4;

    /// The single port a [`ProbeKind::TcpProbe`] scan sends from, and so the port its
    /// answers come back to.
    const SCAN_PORT: u16 = 50_000;

    /// Whether `filter`, compiled for an Ethernet link, admits `frame`.
    ///
    /// A dead capture is a compiler with no interface behind it, so this needs neither
    /// privileges nor a network.
    fn admits(filter: &str, frame: &[u8]) -> bool {
        admits_on(pcap::Linktype::ETHERNET, filter, frame)
    }

    /// Whether `filter`, compiled for a link of type `link`, admits `frame`.
    fn admits_on(link: pcap::Linktype, filter: &str, frame: &[u8]) -> bool {
        let capture = pcap::Capture::dead(link)
            .unwrap_or_else(|e| panic!("opening a dead capture for {link:?}: {e}"));
        let program = capture
            .compile(filter, true)
            .unwrap_or_else(|e| panic!("compiling `{filter}` for {link:?}: {e}"));
        program.filter(frame)
    }

    /// An Ethernet-framed TCP segment carrying `flags`, over whichever family `src`
    /// and `dst` are, addressed back to the port a scan sent from.
    fn tcp_frame(src: IpAddr, dst: IpAddr, flags: u8) -> Vec<u8> {
        tcp_frame_to(src, dst, flags, SCAN_PORT)
    }

    /// [`tcp_frame`] addressed to an explicit port, for filters that narrow on one.
    fn tcp_frame_to(src: IpAddr, dst: IpAddr, flags: u8, dst_port: u16) -> Vec<u8> {
        let mut segment = vec![0u8; TCP_HDR_LEN];
        {
            let mut tcp = MutableTcpPacket::new(&mut segment).expect("TCP header buffer");
            tcp.set_source(443);
            tcp.set_destination(dst_port);
            tcp.set_data_offset((TCP_HDR_LEN / 4) as u8);
            tcp.set_flags(flags);
            tcp.set_window(1024);
        }
        frame(src, dst, IpNextHeaderProtocols::Tcp, &segment)
    }

    /// An Ethernet-framed UDP datagram between the given ports.
    fn udp_frame(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let segment = udp::build_packet(src, dst, src_port, dst_port, vec![0u8; 4])
            .expect("building a UDP datagram");
        frame(src, dst, IpNextHeaderProtocols::Udp, &segment)
    }

    /// An Ethernet-framed SCTP packet between the given ports, carrying the chunk a
    /// probe draws back.
    fn sctp_frame(src: IpAddr, dst: IpAddr, src_port: u16, dst_port: u16) -> Vec<u8> {
        let packet = crate::protocols::sctp::build_init_probe(src_port, dst_port, 0xDEAD_BEEF);
        frame(src, dst, IpNextHeaderProtocols::Sctp, &packet)
    }

    /// An Ethernet-framed ICMPv6 destination-unreachable, the shape a UDP probe draws
    /// from a closed port over IPv6.
    fn icmpv6_error_frame(src: IpAddr, dst: IpAddr) -> Vec<u8> {
        let mut segment = vec![0u8; MutableIcmpv6Packet::minimum_packet_size() + ICMPV6_UNUSED_LEN];
        {
            let mut icmp = MutableIcmpv6Packet::new(&mut segment).expect("ICMPv6 header buffer");
            icmp.set_icmpv6_type(Icmpv6Types::DestinationUnreachable);
            icmp.set_icmpv6_code(Icmpv6Code(4));
        }
        frame(src, dst, IpNextHeaderProtocols::Icmpv6, &segment)
    }

    fn frame(
        src: IpAddr,
        dst: IpAddr,
        protocol: pnet_packet::ip::IpNextHeaderProtocol,
        segment: &[u8],
    ) -> Vec<u8> {
        build_ethernet_frame(
            &FrameSpec {
                src_mac: MacAddr::new(0x02, 0, 0, 0, 0, 0x02),
                dst_mac: MacAddr::new(0x02, 0, 0, 0, 0, 0x01),
                src,
                dst,
                protocol: protocol.0,
                hop_limit: crate::protocols::ip::HOP_LIMIT_ROUTED,
            },
            segment,
        )
        .expect("building an Ethernet frame")
    }

    /// The two send failures that call for opposite responses are told apart by the
    /// operating system's error kind, not its wording.
    ///
    /// Message text differs per platform and locale, so matching on it breaks silently
    /// on other machines. Only the two unreachable kinds are singled out: a full buffer
    /// or a permission failure says nothing about whether the destination exists, and
    /// treating either as unroutable would hide a scan that could not run.
    #[test]
    fn a_destination_with_no_route_is_not_a_broken_send_path() {
        use super::SendError;
        use std::io::{Error, ErrorKind};

        for kind in [ErrorKind::HostUnreachable, ErrorKind::NetworkUnreachable] {
            let error = SendError::from_io(Error::new(
                kind,
                "failed to send to 2001:db8::1: No route to host",
            ));
            assert!(error.is_unroutable(), "{kind:?} is about the destination");
            assert!(
                error.to_string().contains("2001:db8::1"),
                "the address survives the classification: {error}"
            );
        }

        for kind in [
            ErrorKind::PermissionDenied,
            ErrorKind::WouldBlock,
            ErrorKind::BrokenPipe,
        ] {
            let error = SendError::from_io(Error::new(kind, "nope"));
            assert!(
                !error.is_unroutable(),
                "{kind:?} is about this host, not the destination"
            );
        }
    }

    /// The kernel's word for a neighbour it gave up on lately is a fact about the
    /// destination, named as a hold-down, distinct from a resolution this sender waited
    /// out.
    ///
    /// macOS answers every probe to such a neighbour with `EHOSTDOWN` while it
    /// remembers the failure, and `std` has no error kind for it, so it is read by
    /// number. As a refusal it would file a dead address as a broken scanner; as an
    /// unanswered resolution, a failure from before the scan asked would become the
    /// scan's verdict. A full send buffer must stay a refusal beside it, since it is
    /// this host's.
    #[cfg(unix)]
    #[test]
    fn a_neighbour_the_kernel_gave_up_on_is_not_a_broken_send_path() {
        use super::SendError;
        use std::io::Error;

        let error = SendError::from_io(Error::from_raw_os_error(libc::EHOSTDOWN));
        assert!(
            matches!(error, SendError::HeldDown(_)),
            "the kernel's hold-down: {error:?}"
        );
        assert!(error.is_unroutable(), "and about the destination");

        let error = SendError::from_io(Error::from_raw_os_error(libc::ENOBUFS));
        assert!(!error.is_unroutable(), "a full buffer is this host's");
    }

    /// A send refused for want of a descriptor is named by the one fact a reader can
    /// act on, whatever layers it was opened through.
    #[cfg(unix)]
    #[test]
    fn a_send_refused_for_want_of_a_descriptor_says_the_file_limit() {
        use super::SendError;
        use std::io::Error;

        for code in [libc::EMFILE, libc::ENFILE] {
            let error = SendError::from_io(Error::from_raw_os_error(code));
            assert!(
                matches!(error, SendError::OutOfDescriptors),
                "{code}: {error:?}"
            );
            assert!(!error.is_unroutable(), "a fact about this machine");
            assert_eq!(error.to_string(), "file limit reached");
        }
    }

    // ─── TCP SYN ─────────────────────────────────────────────────────────────

    #[test]
    fn the_syn_filter_admits_the_two_answers_a_syn_probe_draws_over_ipv4() {
        let filter = ProbeKind::TcpSyn.filter();

        assert!(
            admits(&filter, &tcp_frame(SRC_V4, DST_V4, SYN | ACK)),
            "a SYN+ACK is an open port and must reach the scanner"
        );
        assert!(
            admits(&filter, &tcp_frame(SRC_V4, DST_V4, RST | ACK)),
            "a RST is a closed port and must reach the scanner"
        );
    }

    /// The filter keeps unrelated traffic out of userspace, so an established
    /// connection's segments must not reach the scanner.
    #[test]
    fn the_syn_filter_rejects_established_traffic_over_ipv4() {
        assert!(!admits(
            &ProbeKind::TcpSyn.filter(),
            &tcp_frame(SRC_V4, DST_V4, ACK)
        ));
    }

    /// `tcp[tcpflags]` is `proto[x]` indexing, which `libpcap` cannot compile over
    /// IPv6, where the next-header chain makes the offset non-constant. It does not
    /// report that: written unqualified it silently narrows the whole expression to
    /// IPv4, and the compiled program jumps straight to `ret #0` on EtherType
    /// `0x86dd`. With the capture as the only receive path, routed IPv6 discovery and
    /// IPv6 SYN port scanning would see no replies.
    #[test]
    fn the_syn_filter_admits_the_same_answers_over_ipv6() {
        let filter = ProbeKind::TcpSyn.filter();

        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, SYN | ACK)));
        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, RST | ACK)));
    }

    /// What admitting the IPv6 half unnarrowed costs.
    ///
    /// An established IPv6 connection's segments reach userspace, where the IPv4
    /// equivalent is dropped by the kernel. The filter cannot help (see
    /// [`libpcap_cannot_narrow_tcp_flags_over_ipv6`]), so the scanners re-check the
    /// flags themselves; this test records the asymmetry next to the filter.
    #[test]
    fn the_ipv6_half_of_the_syn_filter_is_not_narrowed_to_probe_replies() {
        let filter = ProbeKind::TcpSyn.filter();

        assert!(
            !admits(&filter, &tcp_frame(SRC_V4, DST_V4, ACK)),
            "the IPv4 half is narrowed by the kernel"
        );
        assert!(
            admits(&filter, &tcp_frame(SRC_V6, DST_V6, ACK)),
            "the IPv6 half cannot be, so userspace has to do it"
        );
    }

    /// Why the test above cannot be fixed by asking for IPv6 explicitly, and the
    /// constraint any replacement expression must work around.
    ///
    /// Records a `libpcap` limitation the engine designs around. If `libpcap` learns
    /// to index into IPv6, this test will notice.
    #[test]
    fn libpcap_cannot_narrow_tcp_flags_over_ipv6() {
        let narrowed = "ip6 and tcp and (tcp[tcpflags] & (tcp-syn|tcp-rst)) != 0";
        let capture = pcap::Capture::dead(pcap::Linktype::ETHERNET).expect("dead capture");

        let admits_a_syn_ack = capture
            .compile(narrowed, true)
            .map(|program| program.filter(&tcp_frame(SRC_V6, DST_V6, SYN | ACK)))
            .unwrap_or(false);

        assert!(
            !admits_a_syn_ack,
            "libpcap now narrows TCP flags over IPv6; the split filter is no longer needed"
        );
    }

    // ─── TCP port probes ─────────────────────────────────────────────────────

    fn tcp_probe_filter(icmp_errors: bool) -> String {
        ProbeKind::TcpProbe {
            reply_port: SCAN_PORT,
            icmp_errors,
        }
        .filter()
    }

    /// Both answers a port probe can draw, over both families.
    #[test]
    fn the_tcp_probe_filter_admits_answers_addressed_to_the_scan() {
        let filter = tcp_probe_filter(false);

        for (src, dst) in [(SRC_V4, DST_V4), (SRC_V6, DST_V6)] {
            assert!(
                admits(&filter, &tcp_frame(src, dst, SYN | ACK)),
                "a SYN+ACK is an open port and must reach the scanner"
            );
            assert!(
                admits(&filter, &tcp_frame(src, dst, RST | ACK)),
                "a RST is an answer and must reach the scanner"
            );
        }
    }

    /// What narrowing on the scan's own port buys over narrowing on flags, and why a
    /// TCP port scan sends every probe from one port.
    ///
    /// A flag test cannot be compiled over IPv6 (see
    /// [`libpcap_cannot_narrow_tcp_flags_over_ipv6`]), so [`ProbeKind::TcpSyn`] admits
    /// every IPv6 TCP segment on every captured interface and sorts them in userspace.
    /// A destination port compiles for both families, so this filter rejects the
    /// host's other conversations in the kernel over IPv6 as over IPv4.
    #[test]
    fn the_tcp_probe_filter_rejects_traffic_addressed_elsewhere_over_both_families() {
        let filter = tcp_probe_filter(false);
        let elsewhere = SCAN_PORT + 1;

        for (src, dst) in [(SRC_V4, DST_V4), (SRC_V6, DST_V6)] {
            assert!(
                !admits(&filter, &tcp_frame_to(src, dst, RST | ACK, elsewhere)),
                "a segment to a port this scan never sent from is somebody else's"
            );
        }
    }

    /// This filter narrows on the conversation, not the flags, so a segment carrying
    /// neither answer a probe can draw still reaches userspace if addressed to the
    /// scan's port.
    ///
    /// The scan's port is drawn from the high ephemeral range so nothing else on the
    /// host is using it, and the scanner re-checks the flags either way, so this costs
    /// a check per segment, not a wrong verdict.
    #[test]
    fn the_tcp_probe_filter_narrows_on_the_conversation_rather_than_the_flags() {
        let filter = tcp_probe_filter(false);

        assert!(admits(&filter, &tcp_frame(SRC_V4, DST_V4, ACK)));
        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, ACK)));
    }

    /// ICMP is admitted only when a technique's verdicts depend on it, because an ICMP
    /// error names no ports and cannot be narrowed: asking for it copies every ICMP
    /// packet on every captured interface to userspace.
    #[test]
    fn the_tcp_probe_filter_admits_icmp_errors_only_when_asked() {
        let error = icmpv6_error_frame(SRC_V6, DST_V6);

        assert!(!admits(&tcp_probe_filter(false), &error));
        assert!(admits(&tcp_probe_filter(true), &error));
    }

    /// Asking for ICMP must not lose the answers the scan is waiting for, nor widen
    /// what it accepts on the TCP half.
    #[test]
    fn asking_for_icmp_changes_nothing_about_the_tcp_half() {
        let filter = tcp_probe_filter(true);

        assert!(admits(&filter, &tcp_frame(SRC_V6, DST_V6, RST | ACK)));
        assert!(!admits(
            &filter,
            &tcp_frame_to(SRC_V6, DST_V6, RST | ACK, SCAN_PORT + 1)
        ));
    }

    // ─── UDP ─────────────────────────────────────────────────────────────────

    /// The resolver's filter is family-agnostic, as it must be: a DNS or mDNS answer
    /// over IPv6 names hosts as well as one over IPv4.
    #[test]
    fn the_resolve_filter_admits_dns_answers_over_both_families() {
        let filter = ProbeKind::UdpResolve.filter();

        assert!(admits(&filter, &udp_frame(SRC_V4, DST_V4, 53, 40_000)));
        assert!(admits(&filter, &udp_frame(SRC_V6, DST_V6, 53, 40_000)));
        assert!(admits(&filter, &udp_frame(SRC_V6, DST_V6, 5353, 5353)));
        assert!(
            !admits(&filter, &udp_frame(SRC_V6, DST_V6, 12_345, 40_000)),
            "traffic from an unrelated source port is not an answer to anything"
        );
    }

    /// Both answers a UDP probe can draw, over both families. `icmp6` carries the IPv6
    /// half here.
    #[test]
    fn the_udp_probe_filter_admits_direct_replies_and_icmp_errors_over_both_families() {
        const REPLY_PORT: u16 = 40_000;
        let filter = ProbeKind::UdpProbe {
            reply_port: REPLY_PORT,
        }
        .filter();

        assert!(admits(&filter, &udp_frame(SRC_V4, DST_V4, 53, REPLY_PORT)));
        assert!(admits(&filter, &udp_frame(SRC_V6, DST_V6, 53, REPLY_PORT)));
        assert!(admits(&filter, &icmpv6_error_frame(SRC_V6, DST_V6)));
        assert!(
            !admits(&filter, &udp_frame(SRC_V6, DST_V6, 53, REPLY_PORT + 1)),
            "a datagram to a port this scan never sent from is somebody else's"
        );
    }

    /// The SCTP filter, held to the same three claims as the UDP one: both families
    /// admitted, ICMP errors admitted whole, and other associations kept out.
    ///
    /// `sctp` is a protocol keyword libpcap has to know for this to compile, and a
    /// filter that fails to compile is a scanner that reads nothing.
    #[test]
    fn the_sctp_filter_admits_answers_to_the_scan_over_both_families() {
        const REPLY_PORT: u16 = 40_000;
        let filter = ProbeKind::Sctp {
            reply_port: REPLY_PORT,
        }
        .filter();

        assert!(admits(
            &filter,
            &sctp_frame(SRC_V4, DST_V4, 2905, REPLY_PORT)
        ));
        assert!(admits(
            &filter,
            &sctp_frame(SRC_V6, DST_V6, 2905, REPLY_PORT)
        ));
        assert!(admits(&filter, &icmpv6_error_frame(SRC_V6, DST_V6)));
        assert!(
            !admits(&filter, &sctp_frame(SRC_V4, DST_V4, 2905, REPLY_PORT + 1)),
            "a packet to a port this scan never sent from belongs to somebody else"
        );
    }

    // ─── Cooked links ────────────────────────────────────────────────────────

    /// The data-link type `libpcap` opens a PPP link as, `DLT_LINUX_SLL`.
    const LINUX_SLL: pcap::Linktype = pcap::Linktype(113);

    /// `frame`, an Ethernet frame, as a PPP link captures the same packet: the Ethernet
    /// header replaced by the pseudo-header Linux writes there, laid out from
    /// `pcap/sll.h` and naming the same EtherType.
    fn as_cooked(frame: &[u8]) -> Vec<u8> {
        let (ethernet, packet) = frame.split_at(crate::protocols::sizes::ETH_HDR_LEN);
        let mut cooked = vec![
            0x00, 0x00, // packet type: addressed to this host
            0x02, 0x00, // hardware type: ARPHRD_PPP
            0x00, 0x00, // address length: a PPP link has none
            0, 0, 0, 0, 0, 0, 0, 0, // the address, unused
        ];
        cooked.extend_from_slice(&ethernet[12..14]);
        cooked.extend_from_slice(packet);
        cooked
    }

    /// Every filter judges a packet arriving over PPP as it judges the same packet
    /// over Ethernet.
    ///
    /// A filter is compiled for the link it is opened on, and on a cooked link
    /// `libpcap` finds the protocol and IP header at its own offsets. An expression
    /// reaching below IP, through an `ether` qualifier or an offset from the start of
    /// the frame, would compile differently there or fail to compile, and a scan
    /// through a PPP VPN would hear nothing. Only `DLT_LINUX_SLL` is compiled for, as
    /// what a capture of one named link comes up as.
    #[test]
    fn every_filter_judges_a_packet_on_a_cooked_link_as_it_does_on_ethernet() {
        const REPLY_PORT: u16 = 40_000;
        let kinds = [
            ProbeKind::TcpSyn,
            ProbeKind::TcpProbe {
                reply_port: SCAN_PORT,
                icmp_errors: false,
            },
            ProbeKind::TcpProbe {
                reply_port: SCAN_PORT,
                icmp_errors: true,
            },
            ProbeKind::UdpResolve,
            ProbeKind::UdpProbe {
                reply_port: REPLY_PORT,
            },
            ProbeKind::Sctp {
                reply_port: REPLY_PORT,
            },
            ProbeKind::IcmpEcho { identifier: 4242 },
            ProbeKind::IpProtocol { number: 47 },
        ];
        let frames = [
            tcp_frame(SRC_V4, DST_V4, SYN | ACK),
            tcp_frame(SRC_V6, DST_V6, SYN | ACK),
            tcp_frame(SRC_V4, DST_V4, ACK),
            tcp_frame(SRC_V6, DST_V6, ACK),
            tcp_frame_to(SRC_V4, DST_V4, RST | ACK, SCAN_PORT + 1),
            udp_frame(SRC_V4, DST_V4, 53, REPLY_PORT),
            udp_frame(SRC_V6, DST_V6, 53, REPLY_PORT),
            udp_frame(SRC_V6, DST_V6, 12_345, REPLY_PORT + 1),
            sctp_frame(SRC_V4, DST_V4, 2905, REPLY_PORT),
            sctp_frame(SRC_V6, DST_V6, 2905, REPLY_PORT),
            icmpv6_error_frame(SRC_V6, DST_V6),
        ];

        let (mut admitted, mut refused) = (0, 0);
        for kind in kinds {
            let filter = kind.filter();
            for frame in &frames {
                let over_ethernet = admits(&filter, frame);
                assert_eq!(
                    admits_on(LINUX_SLL, &filter, &as_cooked(frame)),
                    over_ethernet,
                    "`{filter}` judged a packet differently over PPP than over Ethernet"
                );
                if over_ethernet {
                    admitted += 1;
                } else {
                    refused += 1;
                }
            }
        }
        // Agreement means nothing if every verdict was the same one.
        assert!(
            admitted > 0 && refused > 0,
            "{admitted} admitted, {refused} refused"
        );
    }
}
