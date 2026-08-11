// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

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

/// Global configuration options for the scanner execution.
///
/// This struct controls the runtime behavior of the application, including
/// UI verbosity, network protocol constraints, and privacy features.
/// It is typically constructed via CLI arguments or a configuration file.
#[derive(Debug, Clone, Default)]
pub struct ZondConfig {
    /// Toggles the display of the startup ASCII banner.
    ///
    /// If `true`, the application starts immediately with log output/spinners
    /// without printing the stylized branding. Useful for clean logs or
    /// frequent executions.
    pub no_banner: bool,

    /// Restricts the scanner from generating outbound DNS traffic.
    ///
    /// # Behavior
    /// * **True**: The scanner will strictly avoid sending DNS queries (A, AAAA, PTR).
    /// * **False** (Default): The scanner may resolve hostnames to IPs or perform reverse lookups.
    ///
    /// **Note:** This does not prevent the underlying OS or network stack from
    /// processing incoming DNS packets if they were initiated elsewhere.
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

    /// Enables privacy mode for sensitive data in the output.
    ///
    /// When enabled, personally identifiable information (PII) or sensitive
    /// network details are masked.
    ///
    /// # Masked Fields
    /// * IPv6 Suffixes (e.g Global Unicast)
    /// * MAC Addresses
    /// * Hostnames
    ///
    /// Use this when sharing screenshots or logs publicly.
    pub redact: bool,

    /// Controls the visual density and formatting of the terminal output.
    ///
    /// This value is typically mapped from the `-q` or `--quiet` CLI flags.
    ///
    /// # Levels
    /// * **0** (Default): Full UI, including colors, spinners, and detailed tables.
    /// * **1**: Reduced styling. Minimal colors, simplified tables.
    /// * **2**: Raw mode. Output is strictly data (e.g., plain IP lists), suitable for piping into other tools.
    pub quiet: u8,

    /// Disables interactive keyboard listeners.
    ///
    /// When `true`, the application will not spawn threads to listen for
    /// runtime commands (like pausing, resuming, or status checks).
    ///
    /// # Use Cases
    /// * Running in a CI/CD pipeline.
    /// * Running as a background system service (daemon).
    /// * Non-interactive testing environments.
    pub disable_input: bool,

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
    /// satisfy. Defaults to [`ScanEffort::Balanced`].
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
