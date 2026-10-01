// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # TCP Scan Techniques
//!
//! Which segment a TCP port probe carries, and what an answer to it proves.
//!
//! The flags on the probe decide which question a port scan asks. A SYN asks "will you
//! accept a connection here?" and is answered positively. The five techniques that do
//! not send one ask "is anyone behind this port?" and are answered *negatively*, by the
//! RST only a closed port is obliged to send; a filter that blocks connection attempts
//! often passes such a segment. The seventh, [`Window`](TcpScanTechnique::Window), reads
//! one field of that refusal that answers positively.
//!
//! The reply-to-verdict mapping lives here because it is all that distinguishes the
//! techniques; retransmission, pacing, source selection and the deadline are shared,
//! and the scanner is written once against this table. The flags themselves live in
//! [`crate::protocols::tcp`].
//!
//! ## What each technique rests on
//!
//! RFC 793 §3.4 requires a port with nothing behind it to answer any segment
//! that does not carry RST with a RST, and requires a port in LISTEN to ignore a segment
//! carrying neither SYN, ACK nor RST. Silence is weak evidence of a listener and a RST
//! strong evidence of none, so the verdict for silence is
//! [`PortState::OpenOrNoReply`].
//!
//! Not every stack obeys. Windows, many Cisco devices, BSDI and IBM OS/400 answer every
//! flag probe with a RST whatever the port state, so [`Fin`](TcpScanTechnique::Fin),
//! [`Null`](TcpScanTechnique::Null), [`Xmas`](TcpScanTechnique::Xmas) and
//! [`Maimon`](TcpScanTechnique::Maimon) report every port closed, confidently and
//! wrongly. A run that finds *no* open-or-no-reply port has almost certainly met one,
//! and is worth repeating with [`Syn`](TcpScanTechnique::Syn).
//!
//! ## No single technique answers the whole question
//!
//! A flag probe cannot tell an open port from one a filter dropped: both are silent and
//! come back [`PortState::OpenOrNoReply`]. An [`Ack`](TcpScanTechnique::Ack) scan tells
//! those two apart but never says which is open. Only [`Syn`](TcpScanTechnique::Syn)
//! identifies a listener from the reply alone. [`Window`](TcpScanTechnique::Window)
//! reads one field further than the ACK scan, separating open from closed on stacks
//! that still leak the difference.
//!
//! Measured against a router with one open, one dropping and three closed ports, the
//! FIN scan reported the open and the dropping port identically, and the ACK scan beside
//! it separated them. The techniques are complementary instruments.

use std::fmt;
use std::str::FromStr;

use crate::model::port::PortState;

/// The two segments a TCP port probe can draw back, as classified off the wire
/// by [`crate::protocols::tcp::classify_probe_response`].
///
/// What either means depends on the probe that provoked it, which is
/// [`TcpScanTechnique::verdict`]'s job: a RST is a closed port to a FIN probe and a
/// reachable one to an ACK probe.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpReply {
    /// SYN+ACK: a listener accepting the connection attempt. Only a SYN can
    /// draw one.
    SynAck,
    /// RST: a refusal. Which refusal depends on what was asked.
    Rst {
        /// The receive window the reset announced.
        ///
        /// A stack resetting a connection it never held has no window to announce,
        /// so this reflects the code path it took. BSD derivatives leave the
        /// listening socket's window on a reset from an open port and zero on one
        /// from a closed port. Only [`TcpScanTechnique::Window`] reads it.
        window: u16,
    },

    /// ACK alone: a *challenge ACK*, the one reply here that does not answer the probe
    /// that drew it.
    ///
    /// A stack sends one when a SYN arrives for a connection it is already half-open on
    /// and the sequence number does not fit that connection's window (RFC 793 §3.9
    /// requires an acknowledgement for an unacceptable segment; RFC 5961 §4 makes it
    /// mandatory for a SYN, to close the blind-reset window). It carries `RCV.NXT`,
    /// acknowledging the earlier attempt that opened the connection.
    ///
    /// Only a listener holds a half-open connection; a closed port resets. So this is
    /// positive evidence of an open port.
    ChallengeAck,
}

/// The two chunks an SCTP port probe can draw back, as classified off the wire
/// by [`crate::protocols::sctp::classify_probe_response`].
///
/// As with [`TcpReply`], meaning depends on the probe, which is
/// [`SctpScanTechnique::verdict`]'s job. An ABORT is a closed port to either technique;
/// an INIT-ACK is an open port to an INIT probe and cannot answer a COOKIE-ECHO.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpReply {
    /// An INIT-ACK: an endpoint accepted the association attempt. The SCTP
    /// analogue of a SYN+ACK, and the only positive answer either technique can
    /// draw.
    InitAck,
    /// An ABORT: a reachable stack refusing outright. The SCTP analogue of a
    /// RST, and what both techniques read as a closed port.
    Abort,
}

/// How an SCTP port is probed.
///
/// The SCTP counterparts of the SYN scan and the FIN family. An INIT is answered
/// whichever way the port stands, so it names open ports and reads silence as a
/// filter. A COOKIE-ECHO is answered only by a port with nothing behind it, so it
/// cannot name an open port and reads silence as open or no reply.
///
/// Both need raw sockets: no kernel builds an SCTP chunk on a caller's behalf, so
/// without them SCTP ports are refused.
///
/// Host discovery always sends an INIT, since only an INIT draws an answer from an
/// open port.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SctpScanTechnique {
    /// An INIT chunk. The default, and the only technique that identifies an
    /// open SCTP port positively.
    ///
    /// RFC 4960 fixes both answers: a listener accepts with an INIT-ACK (§5.1)
    /// and a stack with nothing on that port refuses with an ABORT (§8.4), so
    /// every live endpoint says something and silence means none took it. Neither
    /// answer completes an association, so no port is left half-open.
    #[default]
    Init,
    /// A COOKIE-ECHO chunk carrying a cookie no endpoint minted.
    ///
    /// RFC 4960 §8.4 handles an out-of-the-blue COOKIE-ECHO in two ways. A listener
    /// tries to authenticate the cookie (§5.1.5), fails, and silently discards the
    /// packet. A port with no endpoint falls through to the rule that answers an
    /// unrecognised packet with an ABORT. So an ABORT is a closed port and silence is
    /// everything else.
    ///
    /// Filters written against SCTP scanning block INIT, the chunk that opens an
    /// association, and often say nothing about COOKIE-ECHO. The cost is the positive
    /// result: an open port and a dropped probe are both silent. Use it to find out
    /// whether a range that ignored an INIT scan is dropping SCTP or only INIT.
    CookieEcho,
}

impl SctpScanTechnique {
    /// Every technique, in the order they are documented.
    pub const ALL: &'static [Self] = &[Self::Init, Self::CookieEcho];

    /// The canonical name, which is also what [`FromStr`] accepts and
    /// [`fmt::Display`] renders.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Init => "init",
            Self::CookieEcho => "cookie-echo",
        }
    }

    /// One line describing what the technique is for, short enough to sit
    /// beside the name wherever a front end offers the choice.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::Init => "association attempt; the only one that confirms a listener",
            Self::CookieEcho => "unminted cookie; a closed port answers, an open one stays silent",
        }
    }

    /// What the technique concludes from `reply`, or `None` if that chunk
    /// answers nothing this probe asked.
    ///
    /// Nothing a COOKIE-ECHO sends provokes an INIT-ACK, so one arriving at that scan
    /// belongs to someone else's association and resolves nothing.
    pub const fn verdict(self, reply: SctpReply) -> Option<PortState> {
        match (self, reply) {
            (Self::Init, SctpReply::InitAck) => Some(PortState::Open),
            (Self::Init | Self::CookieEcho, SctpReply::Abort) => Some(PortState::Closed),
            (Self::CookieEcho, SctpReply::InitAck) => None,
        }
    }

    /// What the technique concludes when every attempt goes unanswered.
    ///
    /// An INIT that draws nothing was dropped, since a live stack answers one either
    /// way. A COOKIE-ECHO that draws nothing was either dropped or silently discarded
    /// by a listener, and the probe cannot tell which.
    pub const fn silence_means(self) -> PortState {
        match self {
            Self::Init => PortState::NoReply,
            Self::CookieEcho => PortState::OpenOrNoReply,
        }
    }

    /// Whether this technique can report a port [`PortState::Open`].
    ///
    /// [`Init`](Self::Init) alone, from the INIT-ACK a listener sends. A COOKIE-ECHO
    /// scan's best answer is open or no reply.
    pub const fn finds_open_ports(self) -> bool {
        matches!(self, Self::Init)
    }

    /// How a port nothing answered for is described in an audit line.
    pub const fn silence_label(self) -> &'static str {
        match self {
            Self::Init => "no-reply",
            Self::CookieEcho => "open|no-reply",
        }
    }
}

impl fmt::Display for SctpScanTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error [`SctpScanTechnique::from_str`] returns, listing the SCTP technique names
/// that would have worked.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error(
    "unknown SCTP scan technique '{input}', expected one of: {}",
    Self::expected()
)]
pub struct UnknownSctpTechnique {
    /// What the caller wrote.
    pub input: String,
}

impl UnknownSctpTechnique {
    /// The accepted names, comma-separated, in the order they are documented.
    fn expected() -> String {
        SctpScanTechnique::ALL
            .iter()
            .map(|technique| technique.name())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl FromStr for SctpScanTechnique {
    type Err = UnknownSctpTechnique;

    /// Parses a technique name, ignoring case and surrounding whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::technique::SctpScanTechnique;
    ///
    /// assert_eq!("Cookie-Echo".parse(), Ok(SctpScanTechnique::CookieEcho));
    /// assert!("cookie".parse::<SctpScanTechnique>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().to_ascii_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|technique| technique.name() == name)
            .ok_or_else(|| UnknownSctpTechnique {
                input: s.to_string(),
            })
    }
}

/// How a TCP port is probed.
///
/// Every technique needs raw sockets, and so root. The unprivileged connect fallback can
/// only complete handshakes, which approximates [`Syn`](Self::Syn) alone; asking for
/// another technique without privileges is refused, since a connect scan answers a
/// different question.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcpScanTechnique {
    /// A lone SYN. The default, and the only technique that identifies an open
    /// port positively: a SYN+ACK means a listener accepted the connection
    /// attempt, and a RST means nothing is there.
    ///
    /// Fast and accurate against every stack, but also what a filter most likely
    /// blocks and an IDS most likely logs.
    #[default]
    Syn,
    /// A lone FIN. A closed port answers RST, an open one is required to ignore
    /// it, so silence is the closest thing to a positive result.
    ///
    /// The plainest of the flag probes and the one most likely to pass a
    /// stateless filter that blocks SYN.
    Fin,
    /// No flags at all. Identical to [`Fin`](Self::Fin) at the target, since neither
    /// carries SYN, ACK or RST. An empty flag field gets past filters that match on
    /// FIN, and is trivially matched by any filter that looks for it.
    Null,
    /// FIN, PSH and URG together, lit up like a Christmas tree. Classified
    /// exactly as [`Fin`](Self::Fin) is, since PSH and URG occupy no sequence
    /// space and no stack reads them on a segment for a port it is not holding
    /// open.
    ///
    /// Useful diagnostically: filters and stacks disagree about this combination more
    /// than about either flag alone.
    Xmas,
    /// FIN and ACK together, after Uriel Maimon's finding in *Phrack* 49.
    ///
    /// Works only on some targets, so reach for it last. BSD-derived stacks drop the
    /// segment when the port is open, and against those it works like a FIN scan while
    /// looking more like ordinary connection teardown.
    ///
    /// Against a conformant stack it is wrong. RFC 793 requires a reset for any
    /// ACK-carrying segment on a nonexistent connection, listening or not, so an open
    /// port is reported [`PortState::Closed`], and nothing in the scan reveals it:
    /// against a router whose port 80 answered a SYN with SYN+ACK, this reported port
    /// 80 closed. Use it where a FIN scan has shown the target does *not* reset
    /// everything, and confirm a `Closed` with a second technique.
    Maimon,
    /// A lone ACK. Maps the firewall in front of a port without establishing whether
    /// the port is open.
    ///
    /// A RST means the probe reached the host's stack: [`PortState::Reachable`].
    /// Silence or an ICMP error means something dropped it. Beside a SYN scan, this
    /// separates "no listener" from "never arrived".
    Ack,
    /// A lone ACK, read for the window on the reset it draws.
    ///
    /// The probe is [`Ack`](Self::Ack)'s. A stack that announces its listening
    /// socket's window on the reset from an open port, and zero from a closed one, says
    /// which is which without a SYN being sent. The only technique that finds a
    /// listener from a refusal.
    ///
    /// BSD derivatives, much network hardware and many embedded stacks still carry the
    /// distinction. Linux and current Windows reset with a zero window either way, so
    /// against them the whole range reads closed. A range that comes back almost
    /// entirely open, or closed to the last port, is describing the stack; check it
    /// against a [`Syn`](Self::Syn) scan.
    Window,
}

impl TcpScanTechnique {
    /// Every technique, in the order they are documented, for a front end offering the
    /// choice.
    pub const ALL: &'static [Self] = &[
        Self::Syn,
        Self::Fin,
        Self::Null,
        Self::Xmas,
        Self::Maimon,
        Self::Ack,
        Self::Window,
    ];

    /// The canonical name, which is also what [`FromStr`] accepts and
    /// [`fmt::Display`] renders.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Syn => "syn",
            Self::Fin => "fin",
            Self::Null => "null",
            Self::Xmas => "xmas",
            Self::Maimon => "maimon",
            Self::Ack => "ack",
            Self::Window => "window",
        }
    }

    /// One line describing what the technique is for, short enough to sit
    /// beside the name wherever a front end offers the choice.
    pub const fn summary(self) -> &'static str {
        match self {
            Self::Syn => "half-open connection attempt; the only one that confirms a listener",
            Self::Fin => "bare FIN; a closed port answers, an open one stays silent",
            Self::Null => "no flags set; like FIN, but unlike any real connection",
            Self::Xmas => "FIN, PSH and URG at once; the most unusual segment of the three",
            Self::Maimon => {
                "FIN with ACK; only meaningful against BSD-derived stacks, misleading elsewhere"
            }
            Self::Ack => "bare ACK; maps the firewall rather than the ports behind it",
            Self::Window => {
                "bare ACK read for the reset's window; tells open from closed where a stack leaks it"
            }
        }
    }

    /// What the technique concludes from `reply`, or `None` if that segment
    /// answers nothing this probe asked.
    ///
    /// The `None` cases matter: a SYN+ACK reaching an ACK scan cannot have answered its
    /// probe, and reading it as an open port would trust someone else's traffic.
    pub const fn verdict(self, reply: TcpReply) -> Option<PortState> {
        match (self, reply) {
            // A listener answers a SYN; a RST says nothing holds the port.
            (Self::Syn, TcpReply::SynAck) => Some(PortState::Open),
            (Self::Syn, TcpReply::Rst { .. }) => Some(PortState::Closed),

            // A challenge ACK means the stack is half-open on this connection, which
            // only a listener is. It happens when a SYN+ACK is lost: this host never
            // resets it, the peer stays in SYN-RECEIVED, and every retransmission
            // draws a challenge ACK. Ignoring it would read an open port on a lossy
            // path as no reply.
            (Self::Syn, TcpReply::ChallengeAck) => Some(PortState::Open),

            // No other technique opens a connection, so a bare ACK drawn by a FIN or
            // ACK probe is someone else's traffic that happened to match.

            // Only a closed port must send a RST; silence is `silence_means`.
            (Self::Fin | Self::Null | Self::Xmas | Self::Maimon, TcpReply::Rst { .. }) => {
                Some(PortState::Closed)
            }

            // The probe reached a real stack, which is all an ACK scan establishes.
            (Self::Ack, TcpReply::Rst { .. }) => Some(PortState::Reachable),

            // A non-zero window on the reset is the listening socket's; a port
            // with no socket behind it announces zero.
            (Self::Window, TcpReply::Rst { window }) => Some(if window == 0 {
                PortState::Closed
            } else {
                PortState::Open
            }),

            _ => None,
        }
    }

    /// What the technique concludes when every attempt goes unanswered.
    ///
    /// Any live stack answers a SYN or an ACK, so silence means it was dropped. A flag
    /// probe that draws nothing was either dropped *or* delivered to an open port
    /// required to ignore it, and waiting cannot separate those.
    pub const fn silence_means(self) -> PortState {
        match self {
            Self::Syn | Self::Ack | Self::Window => PortState::NoReply,
            Self::Fin | Self::Null | Self::Xmas | Self::Maimon => PortState::OpenOrNoReply,
        }
    }

    /// Whether this technique can report a port [`PortState::Open`].
    ///
    /// [`Syn`](Self::Syn) from a handshake, [`Window`](Self::Window) from a field of a
    /// refusal. After the other five, the service-detection pass, which fingerprints
    /// open TCP ports, has nothing to do.
    ///
    /// A different question from [`has_connect_fallback`](Self::has_connect_fallback).
    pub const fn finds_open_ports(self) -> bool {
        matches!(self, Self::Syn | Self::Window)
    }

    /// Whether a TCP connect scan asks the same question, and so may stand in
    /// for this technique where the process has no raw sockets.
    ///
    /// [`Syn`](Self::Syn) alone: a completed handshake finds the same listeners, at the
    /// cost of being logged. Every other technique depends on a segment no kernel sends
    /// on a caller's behalf, so without raw sockets the scan is refused.
    pub const fn has_connect_fallback(self) -> bool {
        matches!(self, Self::Syn)
    }

    /// Whether this technique needs ICMP errors as well as TCP segments to
    /// reach its verdict.
    ///
    /// False for [`Syn`](Self::Syn) alone. Admitting ICMP copies every ICMP packet on
    /// every captured interface into userspace, since an ICMP error has no ports to
    /// narrow a kernel filter with. The flag-probe techniques gain a verdict for it
    /// ([`PortState::Blocked`] instead of open or no reply), and an ACK scan learns
    /// which device is filtering. A SYN scan reaches open and closed without it.
    ///
    /// Without ICMP, a SYN scan reads a port a filter refused as [`PortState::NoReply`].
    /// To tell the two apart, set
    /// [`ZondConfig::icmp_evidence`](crate::config::ZondConfig::icmp_evidence), and such
    /// a port reads [`PortState::Blocked`].
    pub const fn reads_icmp_errors(self) -> bool {
        !matches!(self, Self::Syn)
    }
}

impl fmt::Display for TcpScanTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error [`TcpScanTechnique::from_str`] returns. Its message lists the accepted
/// names, built from [`TcpScanTechnique::ALL`], so a front end can print it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
#[error(
    "unknown TCP scan technique '{input}', expected one of: {}",
    Self::expected()
)]
pub struct UnknownTechnique {
    /// What the caller wrote.
    pub input: String,
}

impl UnknownTechnique {
    /// The accepted names, comma-separated, in the order they are documented.
    fn expected() -> String {
        TcpScanTechnique::ALL
            .iter()
            .map(|technique| technique.name())
            .collect::<Vec<_>>()
            .join(", ")
    }
}

impl FromStr for TcpScanTechnique {
    type Err = UnknownTechnique;

    /// Parses a technique name, ignoring case and surrounding whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::technique::TcpScanTechnique;
    ///
    /// assert_eq!("Xmas".parse(), Ok(TcpScanTechnique::Xmas));
    /// assert!("stealth".parse::<TcpScanTechnique>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().to_ascii_lowercase();
        Self::ALL
            .iter()
            .copied()
            .find(|technique| technique.name() == name)
            .ok_or_else(|| UnknownTechnique {
                input: s.to_string(),
            })
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

    /// Every technique round-trips through its own name.
    #[test]
    fn every_technique_parses_back_from_the_name_it_prints() {
        for &technique in TcpScanTechnique::ALL {
            assert_eq!(technique.to_string().parse(), Ok(technique));
        }
    }

    #[test]
    fn parsing_ignores_case_and_surrounding_space() {
        assert_eq!("  MAIMON ".parse(), Ok(TcpScanTechnique::Maimon));
    }

    /// The error names every alternative.
    #[test]
    fn an_unknown_name_is_rejected_with_the_ones_that_would_work() {
        let error = "stealth"
            .parse::<TcpScanTechnique>()
            .unwrap_err()
            .to_string();

        assert!(error.contains("stealth"));
        for &technique in TcpScanTechnique::ALL {
            assert!(
                error.contains(technique.name()),
                "{technique} is missing: {error}"
            );
        }
    }

    /// A RST is a closed port to one technique and a reachable port to another.
    #[test]
    fn a_rst_means_something_different_per_technique() {
        use TcpScanTechnique::*;
        let rst = TcpReply::Rst { window: 8192 };
        assert_eq!(Syn.verdict(rst), Some(PortState::Closed));
        assert_eq!(Fin.verdict(rst), Some(PortState::Closed));
        assert_eq!(Ack.verdict(rst), Some(PortState::Reachable));
        assert_eq!(Window.verdict(rst), Some(PortState::Open));
    }

    /// The window scan: zero is a closed port, anything else an open one.
    #[test]
    fn a_window_scan_reads_the_reset_the_ack_scan_only_counts() {
        use TcpScanTechnique::*;
        assert_eq!(
            Window.verdict(TcpReply::Rst { window: 0 }),
            Some(PortState::Closed)
        );
        assert_eq!(
            Window.verdict(TcpReply::Rst { window: 1 }),
            Some(PortState::Open)
        );
        assert_eq!(
            Ack.verdict(TcpReply::Rst { window: 0 }),
            Ack.verdict(TcpReply::Rst { window: 1 }),
            "an ack scan reads the window it has no use for"
        );
    }

    /// Only a SYN scan has a connect fallback, though a window scan also finds open
    /// ports.
    #[test]
    fn only_a_syn_scan_falls_back_to_connect() {
        for &technique in TcpScanTechnique::ALL {
            assert_eq!(
                technique.has_connect_fallback(),
                technique == TcpScanTechnique::Syn,
                "{technique} would have been answered by a connect scan"
            );
        }
        assert!(TcpScanTechnique::Window.finds_open_ports());
        assert!(!TcpScanTechnique::Window.has_connect_fallback());
    }

    /// Only a SYN can provoke a SYN+ACK, so any other scan ignores one.
    #[test]
    fn only_a_syn_scan_reads_a_syn_ack() {
        for &technique in TcpScanTechnique::ALL {
            let verdict = technique.verdict(TcpReply::SynAck);
            assert_eq!(
                verdict.is_some(),
                technique == TcpScanTechnique::Syn,
                "{technique} read a SYN+ACK it could not have provoked"
            );
        }
    }

    /// Silence is plain no-reply only where every live stack would have answered.
    #[test]
    fn silence_is_open_or_no_reply_exactly_for_the_flag_probes() {
        use TcpScanTechnique::*;
        assert_eq!(Syn.silence_means(), PortState::NoReply);
        assert_eq!(Ack.silence_means(), PortState::NoReply);
        assert_eq!(Window.silence_means(), PortState::NoReply);
        for technique in [Fin, Null, Xmas, Maimon] {
            assert_eq!(technique.silence_means(), PortState::OpenOrNoReply);
        }
    }

    /// Every technique but SYN reads ICMP errors.
    #[test]
    fn only_a_syn_scan_declines_icmp_errors() {
        for &technique in TcpScanTechnique::ALL {
            assert_eq!(
                technique.reads_icmp_errors(),
                technique != TcpScanTechnique::Syn
            );
        }
    }

    // ── SCTP ─────────────────────────────────────────────────────────────────

    /// Every SCTP technique round-trips through its own name.
    #[test]
    fn every_sctp_technique_parses_back_from_the_name_it_prints() {
        for &technique in SctpScanTechnique::ALL {
            assert_eq!(technique.to_string().parse(), Ok(technique));
        }
    }

    #[test]
    fn an_unknown_sctp_name_is_rejected_with_the_ones_that_would_work() {
        let error = "cookie".parse::<SctpScanTechnique>().expect_err("refused");
        let message = error.to_string();
        for &technique in SctpScanTechnique::ALL {
            assert!(
                message.contains(technique.name()),
                "the error should name {}",
                technique.name()
            );
        }
    }

    /// An abort is a closed port whichever chunk drew it. An init-ack is an open port
    /// to an init probe and nothing to a cookie-echo, which cannot provoke one.
    #[test]
    fn an_abort_closes_a_port_for_both_and_an_init_ack_only_for_one() {
        assert_eq!(
            SctpScanTechnique::Init.verdict(SctpReply::Abort),
            Some(PortState::Closed)
        );
        assert_eq!(
            SctpScanTechnique::CookieEcho.verdict(SctpReply::Abort),
            Some(PortState::Closed)
        );
        assert_eq!(
            SctpScanTechnique::Init.verdict(SctpReply::InitAck),
            Some(PortState::Open)
        );
        assert_eq!(
            SctpScanTechnique::CookieEcho.verdict(SctpReply::InitAck),
            None
        );
    }

    /// Only an init can name an open port, and only an init reads silence as a filter.
    #[test]
    fn only_an_init_scan_names_an_open_sctp_port() {
        assert!(SctpScanTechnique::Init.finds_open_ports());
        assert!(!SctpScanTechnique::CookieEcho.finds_open_ports());

        assert_eq!(SctpScanTechnique::Init.silence_means(), PortState::NoReply);
        assert_eq!(
            SctpScanTechnique::CookieEcho.silence_means(),
            PortState::OpenOrNoReply
        );
    }

    /// The audit line's word for silence matches the state silence produces.
    #[test]
    fn the_silence_label_names_the_state_silence_produces() {
        assert_eq!(SctpScanTechnique::Init.silence_label(), "no-reply");
        assert_eq!(
            SctpScanTechnique::CookieEcho.silence_label(),
            "open|no-reply"
        );
    }
}
