// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;
use std::str::FromStr;

use crate::core::models::retry::RetryConfig;
use crate::core::models::technique::TcpScanTechnique;

/// How the privileged (raw) scanners put probe packets on the wire.
///
/// Only affects the raw-socket SYN paths; the unprivileged TCP-connect
/// fallback and the on-link ARP/ICMPv6 [`LocalScanner`](crate::scanner)
/// discovery are unaffected.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum SendMode {
    /// Pick per platform: a raw Layer-4 socket on Unix - which the kernel
    /// routes, ARPs, and fragments for us, and which works through VPN
    /// tunnels - and self-built Layer-2 Ethernet frames on Windows, where the
    /// OS blocks raw-socket TCP sends outright.
    #[default]
    Auto,
    /// Force a raw Layer-4 socket regardless of platform.
    RawSocket,
    /// Force self-built Layer-2 Ethernet frames, bypassing the host IP stack
    /// (and the local firewall / connection tracking that a raw-socket send
    /// still traverses). Requires an Ethernet-capable interface and can't
    /// reach loopback or tunnel-only destinations.
    Ethernet,
}

impl SendMode {
    /// Every mode, in the order a front end should offer them.
    pub const ALL: [SendMode; 3] = [SendMode::Auto, SendMode::RawSocket, SendMode::Ethernet];

    /// The name this mode is written under, wherever it arrives as text.
    pub const fn name(self) -> &'static str {
        match self {
            SendMode::Auto => "auto",
            SendMode::RawSocket => "raw_socket",
            SendMode::Ethernet => "ethernet",
        }
    }
}

impl fmt::Display for SendMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error [`SendMode::from_str`] returns, carrying the names that would have
/// worked so a front end can print it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown send mode '{input}', expected one of: auto, raw_socket, ethernet")]
pub struct UnknownSendMode {
    /// What the caller wrote.
    pub input: String,
}

impl FromStr for SendMode {
    type Err = UnknownSendMode;

    /// Parses a mode name, ignoring case and surrounding whitespace, so a choice
    /// arriving as text - from an argument, a form field, a settings file -
    /// needs no mapping table of its own.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::core::config::SendMode;
    ///
    /// assert_eq!("Ethernet".parse(), Ok(SendMode::Ethernet));
    /// assert!("layer2".parse::<SendMode>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|mode| mode.name() == name)
            .ok_or_else(|| UnknownSendMode {
                input: s.to_string(),
            })
    }
}

/// The knobs a probing strategy is built from, carried together so adding one
/// does not mean threading another parameter through every constructor.
///
/// Not every strategy reads every field: local discovery builds its own
/// Ethernet frames and so has no use for [`SendMode`], while every strategy that
/// sends a probe at all has a use for [`RetryConfig`]. `max_probe_rate` is read
/// by routed host discovery; the other paths pace themselves by other means or,
/// where they burst, have not been measured to need it.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProbeTuning {
    pub send_mode: SendMode,
    pub retry: RetryConfig,
    pub max_probe_rate: Option<u32>,
    /// Which segment a TCP port probe carries. Read only by the raw TCP port
    /// scanner: host discovery asks whether anything is there, which every one
    /// of these techniques answers equally badly, so it stays on SYN.
    pub tcp_technique: TcpScanTechnique,
}

/// What a scan does, and what it is allowed to put on the wire.
///
/// **Every field here changes packets or timing.** Nothing about rendering — no
/// banner, no verbosity, no terminal or keyboard handling — because none of that
/// is the engine's business: it emits `tracing` events and installs no
/// subscriber, so what a run looks like is decided entirely by whoever embeds
/// the crate. A front end's own settings belong to the front end; the engine
/// carries them nowhere and holds no opinion about them.
///
/// That boundary is worth keeping because this type is also the record of *how a
/// scan was run*. [`ScanSettings`](crate::core::report::ScanSettings) is derived
/// from it into every report, and a field that cannot change a finding has no
/// business in the record of one.
#[derive(Debug, Clone, Default)]
pub struct ZondConfig {
    /// Forbids the scan from generating any DNS traffic of its own: no A, AAAA
    /// or PTR queries, and no name resolution to go with the addresses it finds.
    ///
    /// Set when the traffic itself is the problem — a query to a resolver the
    /// target operates announces the scan to whoever runs it, and on an
    /// engagement that can be the whole of what goes wrong. The cost is hosts
    /// reported by address alone.
    ///
    /// It governs what this engine sends and nothing else. Traffic the host's
    /// own stack generates for its own reasons is outside anything this crate
    /// can promise.
    pub no_dns: bool,

    /// Whether discovery may probe the whole segment rather than only the
    /// addresses it was given.
    ///
    /// A segment sweep sends the ICMPv6 all-nodes echo, which every IPv6
    /// neighbour may answer, and records the ones that do even though nobody
    /// named them. That is the right behaviour for `zond lan` — the caller asked
    /// about a network, and an IPv6 neighbour with no address in the IPv4 range
    /// is found through this and nothing else. It is the wrong behaviour for
    /// `zond <address>`: scanning one host should not wake its neighbours, and a
    /// report listing eight machines when one was asked about is both surprising
    /// and, on someone else's network, indiscreet.
    ///
    /// Off by default, so the surprising behaviour is the one that has to be
    /// asked for. Only the front end knows which the user meant — the engine
    /// receives an already-resolved set of addresses and cannot tell `lan` from
    /// the range it expanded to — so this has to be set by whoever parsed the
    /// target expression.
    pub segment_sweep: bool,

    /// Whether identifying detail should be masked wherever the scan's findings
    /// leave the process: hostnames, hardware addresses, and the host part of an
    /// IPv6 address.
    ///
    /// For a report going somewhere that needs to know a network's shape without
    /// knowing which device is which — a client, an auditor, a screenshot in an
    /// issue.
    ///
    /// The engine does not mask anything itself; a scan holds what it found. This
    /// records the caller's intent, and it reaches the point of use through
    /// [`ScanSettings`](crate::core::report::ScanSettings) and the export layer's
    /// own [`Redaction`](crate::export::Redaction) policy. Masking on the way out
    /// rather than on the way in is deliberate: the alternative is a report that
    /// has quietly lost data nobody can recover.
    pub redact: bool,

    /// How raw SYN probes are placed on the wire. Defaults to
    /// [`SendMode::Auto`], which is correct on every supported platform;
    /// override it only to force Layer-2 sends for host-stack-bypass scanning.
    pub send_mode: SendMode,

    /// The fastest routed discovery may put probes on the wire, in probes per
    /// second. `None` leaves the scanner's own default in force.
    ///
    /// This is a coverage control before it is a politeness one. A probe's
    /// chance of being answered falls as the rate rises: on a policed path a
    /// burst loses most of its first attempt and the loss is recovered, if at
    /// all, by retransmitting into a quieter moment. Lowering the rate buys
    /// coverage on the first attempt instead, and raising it trades coverage
    /// for the time a large range takes to emit.
    pub max_probe_rate: Option<u32>,

    /// Which segment a TCP port probe carries, and so what its answers mean.
    ///
    /// Defaults to [`TcpScanTechnique::Syn`], which is the only technique that
    /// identifies an open port positively and the only one the unprivileged
    /// connect fallback can approximate. The rest need raw sockets; asking for
    /// one without them records a failure rather than quietly substituting a
    /// connect scan, because the two answer different questions.
    ///
    /// Affects the port-scan phase only. [`discover`](crate::scanner::discover)
    /// is unaffected.
    pub tcp_technique: TcpScanTechnique,

    /// How hard the scan tries before accepting silence as an answer.
    ///
    /// Every probing path has its own schedule, tuned to what its protocol
    /// requires; this scales those rather than replacing them, so raising or
    /// lowering the effort cannot hand a scanner a schedule its protocol cannot
    /// satisfy. Defaults to
    /// [`ScanEffort::Balanced`](crate::core::models::retry::ScanEffort::Balanced).
    pub retry: RetryConfig,
}

impl ZondConfig {
    /// The probe-level knobs, bundled for the strategies that need them.
    pub fn probe_tuning(&self) -> ProbeTuning {
        ProbeTuning {
            send_mode: self.send_mode,
            retry: self.retry,
            max_probe_rate: self.max_probe_rate,
            tcp_technique: self.tcp_technique,
        }
    }
}
