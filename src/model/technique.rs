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
//! A port scan asks a target one question, and the flags on the probe decide
//! which question that is. A SYN asks "will you accept a connection here?" and
//! is answered positively; the five flag-probe techniques ask "is there anyone
//! behind this port at all?" and are answered *negatively*, by the RST that
//! only a closed port is obliged to send. That inversion is the point of them:
//! a filter that blocks connection attempts often passes a segment that is not
//! one, so the probe reaches a stack that a SYN never would.
//!
//! The mapping from reply to verdict lives here rather than in the scanner
//! because it is the whole of what distinguishes the techniques. Everything
//! else - retransmission, pacing, source selection, the deadline - is identical
//! across all six, and the scanner is written once against this table. The
//! flags themselves live in [`crate::protocols::tcp`], which is the layer that
//! knows what a TCP header is.
//!
//! ## What each technique rests on
//!
//! RFC 793 §3.4 requires a port with nothing behind it to answer any segment
//! that does not carry RST with a RST, and requires a port in LISTEN to ignore
//! a segment carrying neither SYN, ACK nor RST. Silence is therefore weak
//! evidence of a listener and a RST is strong evidence of none - which is why
//! [`PortState::OpenFiltered`] is the honest verdict for silence here, and
//! [`PortState::Filtered`] is not.
//!
//! **Not every stack obeys.** Windows, many Cisco devices, BSDI and IBM OS/400
//! answer every flag probe with a RST whatever the port state. Against those,
//! [`Fin`](TcpScanTechnique::Fin), [`Null`](TcpScanTechnique::Null),
//! [`Xmas`](TcpScanTechnique::Xmas) and [`Maimon`](TcpScanTechnique::Maimon)
//! report every port closed - not merely useless but confidently wrong. A run
//! that finds *no* open-filtered port at all has almost certainly met one, and
//! is worth repeating with [`Syn`](TcpScanTechnique::Syn).
//!
//! ## No technique here answers the whole question
//!
//! These are not six ways of doing the same thing, and running one of them is
//! rarely enough. A flag probe cannot tell an open port from a filtered one -
//! both are silent, and both come back [`PortState::OpenFiltered`]. An
//! [`Ack`](TcpScanTechnique::Ack) scan tells those two apart and never says
//! which is open. Only [`Syn`](TcpScanTechnique::Syn) identifies a listener.
//!
//! Measured against a router with one open, one filtered and three closed
//! ports, that plays out exactly: the FIN scan reports the open port and the
//! filtered port identically, and it takes the ACK scan beside it to separate
//! them. A caller offering these to a user is offering complementary
//! instruments, not alternatives.

use std::fmt;
use std::str::FromStr;

use crate::model::port::PortState;

/// The two segments a TCP port probe can draw back, as classified off the wire
/// by [`crate::protocols::tcp::classify_probe_response`].
///
/// What either one *means* depends entirely on the probe that provoked it, which
/// is [`TcpScanTechnique::verdict`]'s job. A RST is a closed port to a FIN probe
/// and an unfiltered path to an ACK probe; naming the segment rather than the
/// conclusion is what keeps the two from being confused.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpReply {
    /// SYN+ACK: a listener accepting the connection attempt. Only a SYN can
    /// draw one.
    SynAck,
    /// RST: a refusal. Which refusal depends on what was asked.
    Rst,
}

/// How a TCP port is probed.
///
/// Every technique here needs raw sockets, and so root; the unprivileged connect
/// fallback can only complete handshakes, which is [`Syn`](Self::Syn) and
/// nothing else. A caller asking for another technique without privileges is
/// told so rather than quietly given a connect scan, because the two answer
/// different questions.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TcpScanTechnique {
    /// A lone SYN. The default, and the only technique that identifies an open
    /// port positively: a SYN+ACK means a listener accepted the connection
    /// attempt, and a RST means nothing is there.
    ///
    /// Fast, accurate against every stack, and the most widely recognized -
    /// which is also its weakness, since it is what a filter is most likely to
    /// block and an IDS most likely to log.
    #[default]
    Syn,
    /// A lone FIN. A closed port answers RST, an open one is required to ignore
    /// it, so silence is the closest thing to a positive result.
    ///
    /// The plainest of the flag probes and the one most likely to pass a
    /// stateless filter that blocks SYN.
    Fin,
    /// No flags at all. Semantically identical to [`Fin`](Self::Fin) at the
    /// target - neither carries SYN, ACK or RST - but a segment with an
    /// empty flag field is unlike anything a real connection produces, so it
    /// gets past filters that match on FIN and is trivially matched by any
    /// filter that thinks to look.
    Null,
    /// FIN, PSH and URG together, lit up like a Christmas tree. Classified
    /// exactly as [`Fin`](Self::Fin) is, since PSH and URG occupy no sequence
    /// space and no stack reads them on a segment for a port it is not holding
    /// open.
    ///
    /// Its value over the other two is diagnostic: three unusual flags at once
    /// is a combination filters and stacks disagree about more than either
    /// alone.
    Xmas,
    /// FIN and ACK together, after Uriel Maimon's finding in *Phrack* 49.
    ///
    /// The one technique whose usefulness is a property of the target rather
    /// than of the RFC, and the one to reach for last. BSD-derived stacks drop
    /// the segment when the port is open, and against those it works like a FIN
    /// scan while looking far more like ordinary connection teardown.
    ///
    /// **Against a conformant stack it is actively misleading.** RFC 793
    /// requires a reset for any ACK-carrying segment on a connection that does
    /// not exist, whether or not the port is listening, so an open port answers
    /// exactly as a closed one does and is reported [`PortState::Closed`].
    /// That is not a missing result but a wrong one, and nothing in the scan
    /// distinguishes it from the truth: measured against a router whose port 80
    /// is open and answers a SYN with SYN+ACK, this technique reported that
    /// port closed. Use it where a FIN scan has already shown the target does
    /// *not* reset everything, and read a `Closed` from it against a second
    /// technique before believing it.
    Maimon,
    /// A lone ACK. Never establishes whether a port is open - it maps the
    /// firewall in front of it.
    ///
    /// A RST means the probe reached the host's stack, which is
    /// [`PortState::Unfiltered`]: something is there and nothing dropped the
    /// segment on the way. Silence or an ICMP error means something did. Running
    /// this beside a SYN scan is what separates "no listener" from "never
    /// arrived".
    Ack,
}

impl TcpScanTechnique {
    /// Every technique, in the order they are documented.
    ///
    /// Exists so a front end offering the choice enumerates it from the engine
    /// rather than from a list of its own that drifts the first time one is
    /// added.
    pub const ALL: [Self; 6] = [
        Self::Syn,
        Self::Fin,
        Self::Null,
        Self::Xmas,
        Self::Maimon,
        Self::Ack,
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
        }
    }

    /// What the technique concludes from `reply`, or `None` if that segment
    /// answers nothing this probe asked.
    ///
    /// The `None` cases are as load-bearing as the others. A SYN+ACK reaching an
    /// ACK scan did not answer its probe - nothing this scan sent could provoke
    /// one - and reading it as an open port would report a listener on the
    /// strength of somebody else's traffic.
    pub const fn verdict(self, reply: TcpReply) -> Option<PortState> {
        match (self, reply) {
            // A SYN is the only probe a listener answers, and a RST to it is the
            // stack saying nothing holds that port.
            (Self::Syn, TcpReply::SynAck) => Some(PortState::Open),
            (Self::Syn, TcpReply::Rst) => Some(PortState::Closed),

            // A RST is what only a closed port is obliged to send; the silence
            // of an open one is handled by `silence_means`.
            (Self::Fin | Self::Null | Self::Xmas | Self::Maimon, TcpReply::Rst) => {
                Some(PortState::Closed)
            }

            // The probe reached a real stack, which is all an ACK scan claims to
            // establish. Whether anything is listening it cannot say.
            (Self::Ack, TcpReply::Rst) => Some(PortState::Unfiltered),

            _ => None,
        }
    }

    /// What the technique concludes when every attempt goes unanswered.
    ///
    /// The difference between the two answers is the difference between the
    /// families. A SYN or an ACK that draws nothing was dropped - both are
    /// answered by any live stack, so silence is a filter. A flag probe that
    /// draws nothing was either dropped *or* delivered to an open port that was
    /// required to ignore it, and no amount of waiting separates those.
    pub const fn silence_means(self) -> PortState {
        match self {
            Self::Syn | Self::Ack => PortState::Filtered,
            Self::Fin | Self::Null | Self::Xmas | Self::Maimon => PortState::OpenFiltered,
        }
    }

    /// Whether this technique can report a port [`PortState::Open`].
    ///
    /// Only [`Syn`](Self::Syn) can. It is worth asking before promising a user
    /// open ports, and it is why the service-detection pass, which fingerprints
    /// open TCP ports, finds nothing to do after any other technique.
    pub const fn finds_open_ports(self) -> bool {
        matches!(self, Self::Syn)
    }

    /// Whether the scan should ask its capture for ICMP errors as well as TCP
    /// segments.
    ///
    /// False for [`Syn`](Self::Syn) alone, and the asymmetry is deliberate.
    /// Admitting ICMP means every ICMP packet on every captured interface is
    /// copied into userspace, since an ICMP error carries no ports to narrow a
    /// kernel filter with. That buys the flag-probe techniques an actual change
    /// of verdict - [`PortState::Filtered`] where silence would have said
    /// open-filtered - and buys an ACK scan the identity of the device doing the
    /// filtering, which is the entire question it was asked. A SYN scan reaches
    /// the same verdict from silence either way.
    pub const fn reads_icmp_errors(self) -> bool {
        !matches!(self, Self::Syn)
    }
}

impl fmt::Display for TcpScanTechnique {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error [`TcpScanTechnique::from_str`] returns, carrying the list of names
/// that would have worked so a front end can print it verbatim.
///
/// The list is built from [`TcpScanTechnique::ALL`] rather than written out, so
/// a technique added there appears in the error that exists to enumerate them.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
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

    /// Parses a technique name, ignoring case and surrounding whitespace, so a
    /// choice arriving as text - from an argument, a form field, a config file -
    /// needs no mapping table of its own.
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
            .into_iter()
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

    /// Every technique round-trips through its own name, so the name a caller
    /// asks by and the one a report answers with can never drift apart.
    #[test]
    fn every_technique_parses_back_from_the_name_it_prints() {
        for technique in TcpScanTechnique::ALL {
            assert_eq!(technique.to_string().parse(), Ok(technique));
        }
    }

    #[test]
    fn parsing_ignores_case_and_surrounding_space() {
        assert_eq!("  MAIMON ".parse(), Ok(TcpScanTechnique::Maimon));
    }

    /// The error names the alternatives, since it is printed straight at a user
    /// who has just mistyped a flag — and it names *every* one, because it is
    /// built from `ALL` rather than from a list that has to be remembered.
    #[test]
    fn an_unknown_name_is_rejected_with_the_ones_that_would_work() {
        let error = "stealth"
            .parse::<TcpScanTechnique>()
            .unwrap_err()
            .to_string();

        assert!(error.contains("stealth"));
        for technique in TcpScanTechnique::ALL {
            assert!(
                error.contains(technique.name()),
                "{technique} is missing: {error}"
            );
        }
    }

    /// The near-miss the whole table exists to prevent: a RST is a closed port
    /// to one technique and an unfiltered path to another, and only the probe
    /// that drew it says which.
    #[test]
    fn a_rst_means_something_different_per_technique() {
        use TcpScanTechnique::*;
        assert_eq!(Syn.verdict(TcpReply::Rst), Some(PortState::Closed));
        assert_eq!(Fin.verdict(TcpReply::Rst), Some(PortState::Closed));
        assert_eq!(Ack.verdict(TcpReply::Rst), Some(PortState::Unfiltered));
    }

    /// Only a SYN can provoke a SYN+ACK, so one arriving at any other scan
    /// answered something else and must not be read as an open port.
    #[test]
    fn only_a_syn_scan_reads_a_syn_ack() {
        for technique in TcpScanTechnique::ALL {
            let verdict = technique.verdict(TcpReply::SynAck);
            assert_eq!(
                verdict.is_some(),
                technique.finds_open_ports(),
                "{technique} read a SYN+ACK it could not have provoked"
            );
        }
    }

    /// Silence is a filter only where every live stack would have answered.
    /// Getting this backwards would report open ports as filtered on the
    /// techniques whose positive result *is* silence.
    #[test]
    fn silence_is_open_filtered_exactly_for_the_flag_probes() {
        use TcpScanTechnique::*;
        assert_eq!(Syn.silence_means(), PortState::Filtered);
        assert_eq!(Ack.silence_means(), PortState::Filtered);
        for technique in [Fin, Null, Xmas, Maimon] {
            assert_eq!(technique.silence_means(), PortState::OpenFiltered);
        }
    }

    /// An ICMP error changes a flag probe's verdict and names an ACK scan's
    /// firewall; for a SYN scan it confirms what silence already concluded, and
    /// admitting ICMP costs every ICMP packet on the host.
    #[test]
    fn only_a_syn_scan_declines_icmp_errors() {
        for technique in TcpScanTechnique::ALL {
            assert_eq!(
                technique.reads_icmp_errors(),
                technique != TcpScanTechnique::Syn
            );
        }
    }
}
