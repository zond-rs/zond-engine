// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use crate::detect::DetectionEnvelope;
use crate::evasion::EvasionProfile;
use crate::model::exclusion::Exclusions;
use crate::model::technique::TcpScanTechnique;

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
    /// use zond_engine::config::SendMode;
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

/// How much effort a scan spends before accepting silence as an answer.
///
/// Every probing path has its own tuned
/// [`RetryPolicy`](crate::scanner::pacing::retry::RetryPolicy), set against what its
/// protocol actually requires - a SYN is answered as fast as the path allows, an
/// ICMP error only as fast as the host is permitted to send one. This scales
/// that starting point rather than replacing it, so choosing "fast" does not
/// quietly hand the UDP scanner a schedule its protocol cannot satisfy.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ScanEffort {
    /// One probe per target and no repeats.
    ///
    /// A first-class choice rather than a disabled feature: it is what an
    /// address-space-scale sweep wants, where per-probe state cannot be afforded
    /// and coverage is bought with a second pass instead.
    Single,
    /// Fewer attempts and less patience. For a network already known to be
    /// healthy, where a missed host is cheaper than the time spent confirming
    /// one is absent.
    Fast,
    #[default]
    Balanced,
    /// More attempts, more patience, and no shortcuts on hosts that stay
    /// silent. For a lossy path, or a result someone is going to act on.
    Thorough,
}

impl ScanEffort {
    /// Every level, ordered from least effort to most.
    pub const ALL: [ScanEffort; 4] = [
        ScanEffort::Single,
        ScanEffort::Fast,
        ScanEffort::Balanced,
        ScanEffort::Thorough,
    ];

    /// The name this level is written under, wherever it arrives as text.
    pub const fn name(self) -> &'static str {
        match self {
            ScanEffort::Single => "single",
            ScanEffort::Fast => "fast",
            ScanEffort::Balanced => "balanced",
            ScanEffort::Thorough => "thorough",
        }
    }
}

impl std::fmt::Display for ScanEffort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The error parsing a [`ScanEffort`] returns, carrying the names that would
/// have worked so a front end can print it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("unknown scan effort '{input}', expected one of: single, fast, balanced, thorough")]
pub struct UnknownScanEffort {
    /// What the caller wrote.
    pub input: String,
}

impl std::str::FromStr for ScanEffort {
    type Err = UnknownScanEffort;

    /// Parses an effort name, ignoring case and surrounding whitespace, so a
    /// choice arriving as text - from an argument, a form field, a settings
    /// file - needs no mapping table of its own.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::ScanEffort;
    ///
    /// assert_eq!("Thorough".parse(), Ok(ScanEffort::Thorough));
    /// assert!("maximum".parse::<ScanEffort>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let name = s.trim().to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|effort| effort.name() == name)
            .ok_or_else(|| UnknownScanEffort {
                input: s.to_string(),
            })
    }
}

/// How far a scan goes to identify the operating system behind a host.
///
/// Four levels, ordered by what they put on the wire. The ordering is the point:
/// each level is a superset of the one below it, so raising the level only ever
/// adds evidence and never trades one technique for another. That is what makes
/// [`is_active`](Self::is_active) — "may this send packets of its own?" — a
/// question with a single answer, and what lets a front end offer this as a dial
/// rather than a menu.
///
/// # Why the default is on
///
/// [`Passive`](Self::Passive) sends **nothing at all**. Every signal it reads is
/// already in a reply the scan drew for another reason: the hop count, the
/// fragmentation policy and the identifier in an IP header the capture used to
/// arrive at, and the window and options of a segment the port scanner was
/// waiting for anyway. A scan with it on and a scan with it off emit
/// byte-identical traffic and take the same time, so there is nothing for a
/// caller to weigh, and defaulting it off would mean a finding thrown away for
/// no consideration.
///
/// [`Off`](Self::Off) exists all the same, for the caller who wants a report to
/// contain only what was asked for, and for reproducing a run that predates any
/// of this.
///
/// # Why the higher levels are not
///
/// From [`Active`](Self::Active) upward this costs packets. Not, today, unusual
/// ones — what it sends is a SYN and a ping, and the SYN is byte-for-byte the
/// segment a port scan already sends. What it is, is **extra**: a host is asked
/// several more times than classifying its ports required, and it is asked at
/// addresses a caller may only have meant to enumerate. Traffic sent for a
/// second purpose has to be asked for even when its shape gives nothing away,
/// which is the whole reason this is a dial and not a default.
///
/// It also becomes true in the older sense as the tiers fill in.
/// [`Aggressive`](Self::Aggressive) is where a deliberately malformed probe
/// would live — traffic identified by how a stack *mishandles* it, and so by
/// construction what an intrusion-detection system was written to notice. None
/// is sent yet; the level is documented for what it does rather than for what it
/// is named after.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OsDetection {
    /// Level 0. Identify nothing, and record nothing about the stacks that
    /// answered.
    Off,

    /// Level 1, and the default. Read the operating system out of replies the
    /// scan already drew, and send nothing extra.
    ///
    /// Answers at the level of a family — the shape of a stack, not its version
    /// — and answers only for hosts that replied to something. A host that
    /// answered no probe at all leaves nothing to read.
    #[default]
    Passive,

    /// Level 2. Everything [`Passive`](Self::Passive) reads, plus probes of this
    /// engine's own aimed at the hosts whose replies were not enough.
    ///
    /// Ordinary, well-formed packets — nothing here is malformed, and nothing
    /// carries a flag combination a real connection does not. Two probes:
    ///
    /// - **A series of SYNs**, to a host with an open or closed TCP port. The
    ///   same segment a SYN scan sends, repeated from a fresh source port each
    ///   time, because whether a stack's IP identifier counts or is random,
    ///   whether its sequence numbers are hashed or stepped, and how fast its
    ///   timestamp clock ticks are *policies* — visible across several replies
    ///   and in no single one. These are the features a release-level rule turns
    ///   on.
    /// - **One SNMP request**, to a host whose kernel is still unknown. On a Unix
    ///   host `sysDescr` is the output of `uname -a`, so an agent that answers
    ///   states the exact kernel — the one thing no amount of packet analysis
    ///   can establish, and what a known-vulnerability lookup keys on. Sent with
    ///   the default `public` community, read-only, for one object.
    /// - **One ICMP echo**, to a host that answered no TCP probe at all. A stock
    ///   Windows firewall drops rather than refuses, so a desktop with nothing
    ///   exposed emits no segment any TCP rule could read; a ping is the one
    ///   packet it still answers.
    ///
    /// None of them touches the port list. A detection level says how hard to
    /// look at a host, not which ports to scan, and a level that quietly widened
    /// `--ports` would send probes at a port the caller excluded.
    ///
    /// The traffic is unremarkable in shape but it is extra, and it is addressed
    /// at hosts the caller may only have meant to enumerate. It is spent where
    /// the passive evidence was thin rather than on everything.
    Active,

    /// Level 3. The same probes [`Active`](Self::Active) sends, more of them,
    /// and at every host rather than only the unsettled ones.
    ///
    /// Twice the samples per host, and hosts already named with high confidence
    /// are followed too. That is what somebody *measuring* wants — a reading
    /// from a machine whose operating system they already know is how a rule
    /// gets authored — and it is more traffic, sustained longer, at more
    /// addresses, which is why it is a level of its own.
    ///
    /// # What this level does not yet do
    ///
    /// It sends no deliberately malformed probe. Reserved fields set, flag
    /// combinations no connection produces, headers that disagree with their own
    /// lengths — these separate stacks that agree on everything legal, and they
    /// are the obvious next tier. They are not here because this engine authors
    /// rules from what it has measured through its own probes, and nothing has
    /// yet measured those. When they arrive they arrive at this level; until
    /// then this is the honest description of it rather than a promise.
    Aggressive,
}

impl OsDetection {
    /// Every level, ordered from least effort to most. The index of a level in
    /// this array is its [`level`](Self::level) number.
    pub const ALL: [OsDetection; 4] = [
        OsDetection::Off,
        OsDetection::Passive,
        OsDetection::Active,
        OsDetection::Aggressive,
    ];

    /// The name this level is written under, wherever it arrives as text.
    pub const fn name(self) -> &'static str {
        match self {
            OsDetection::Off => "off",
            OsDetection::Passive => "passive",
            OsDetection::Active => "active",
            OsDetection::Aggressive => "aggressive",
        }
    }

    /// The number this level is written as, for a front end that offers it as a
    /// dial rather than a word.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::OsDetection;
    ///
    /// assert_eq!(OsDetection::default().level(), 1);
    /// ```
    pub const fn level(self) -> u8 {
        match self {
            OsDetection::Off => 0,
            OsDetection::Passive => 1,
            OsDetection::Active => 2,
            OsDetection::Aggressive => 3,
        }
    }

    /// The level with this number, or `None` past the highest there is.
    ///
    /// Deliberately not saturating. A caller who writes `9` meaning "as much as
    /// possible" has written something this engine does not offer, and silently
    /// giving them the top level would hide it — the same reasoning that makes
    /// [`from_str`](Self::from_str) refuse a name it does not know rather than
    /// fall back to the default.
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(OsDetection::Off),
            1 => Some(OsDetection::Passive),
            2 => Some(OsDetection::Active),
            3 => Some(OsDetection::Aggressive),
            _ => None,
        }
    }

    /// Whether identification happens at all.
    pub const fn is_enabled(self) -> bool {
        !matches!(self, OsDetection::Off)
    }

    /// Whether this level may put probes of its own on the wire.
    ///
    /// The question every caller with a reason to care is actually asking. A
    /// scan that must add no traffic of its own, and a report that has to say
    /// whether it did, both turn on this and not on which level was chosen.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::OsDetection;
    ///
    /// assert!(!OsDetection::Passive.is_active(), "the default sends nothing");
    /// assert!(OsDetection::Aggressive.is_active());
    /// ```
    pub const fn is_active(self) -> bool {
        matches!(self, OsDetection::Active | OsDetection::Aggressive)
    }
}

impl fmt::Display for OsDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error parsing an [`OsDetection`] returns, carrying the values that would
/// have worked so a front end can print it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown OS detection level '{input}', expected one of: off, passive, active, aggressive \
     (or 0, 1, 2, 3)"
)]
pub struct UnknownOsDetection {
    /// What the caller wrote.
    pub input: String,
}

impl FromStr for OsDetection {
    type Err = UnknownOsDetection;

    /// Parses a level by name or by number, ignoring case and surrounding
    /// whitespace, so a choice arriving as text - from an argument, a form
    /// field, a settings file - needs no mapping table of its own.
    ///
    /// Both spellings are accepted because both are how this is written in
    /// practice: a settings file says `passive`, and a command line says `2`.
    /// Splitting them across two entry points would put the correspondence
    /// between the word and the number in whoever called this, and two front ends
    /// would eventually disagree about it.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::OsDetection;
    ///
    /// assert_eq!("Aggressive".parse(), Ok(OsDetection::Aggressive));
    /// assert_eq!("0".parse(), Ok(OsDetection::Off));
    /// assert!("maximum".parse::<OsDetection>().is_err());
    /// ```
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let written = s.trim().to_ascii_lowercase();

        if let Ok(level) = written.parse::<u8>()
            && let Some(detection) = Self::from_level(level)
        {
            return Ok(detection);
        }

        Self::ALL
            .into_iter()
            .find(|detection| detection.name() == written)
            .ok_or_else(|| UnknownOsDetection {
                input: s.to_string(),
            })
    }
}

/// How far a scan may go to identify what is listening behind an open port.
///
/// The port-scan phase establishes that a port is *open*; naming what is on it
/// is a second pass, and unlike the first it needs a real connection. That is
/// the cost this dial governs. It is worth governing separately because the two
/// have different audiences: a scan mapping what exists wants the ports, and a
/// scan auditing what is deployed wants the names, and the second costs a
/// conversation with every open port.
///
/// Ordered by what each level puts on the wire, so a caller can compare two
/// levels and a report can record which was asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceDetection {
    /// Level 0. Do not connect. A port keeps whatever its number implies and
    /// nothing more.
    ///
    /// The fastest and the quietest: after a raw scan, no connection is ever
    /// completed, so nothing appears in the target's logs and nothing is read
    /// from any service. What it costs is every version and every product — a
    /// port reported `open http` on the strength of being port 80, which may be
    /// anything at all.
    Off,
    /// Level 1. Connect and listen. Send nothing.
    ///
    /// For services that greet on connect — SSH, SMTP, FTP, IRC — this is the
    /// whole of what a probe would have learned anyway, and it is obtained
    /// without putting a single byte on the wire. For everything else it
    /// establishes only that the port accepts connections.
    ///
    /// The level to reach for against equipment that must not be sent anything
    /// unexpected. Industrial controllers, medical devices and old embedded
    /// stacks have all been knocked over by a well-formed request they did not
    /// anticipate, and on those networks the right amount to send is nothing.
    Banner,
    /// Level 2, and the default. Connect, listen, and ask.
    ///
    /// Sends each port the probes its service registered, and — where nothing
    /// registers the port — the one generic request worth asking of anything.
    /// That last part is what identifies the long tail: an open port on a number
    /// nobody registered is most often an HTTP server, and one request names it.
    ///
    /// The default, because it is both the most informative level and, against
    /// an unrecognised port, the *fastest*. The alternative to asking is waiting
    /// for a greeting that never comes and then guessing at TLS, which costs two
    /// seconds per port to learn nothing. A scan that asks gets an answer in a
    /// round trip.
    #[default]
    Probe,
}

impl ServiceDetection {
    /// Every level, ordered from least effort to most. The index of a level in
    /// this array is its [`level`](Self::level) number.
    pub const ALL: [ServiceDetection; 3] = [
        ServiceDetection::Off,
        ServiceDetection::Banner,
        ServiceDetection::Probe,
    ];

    /// The name this level is written under, wherever it arrives as text.
    pub const fn name(self) -> &'static str {
        match self {
            ServiceDetection::Off => "off",
            ServiceDetection::Banner => "banner",
            ServiceDetection::Probe => "probe",
        }
    }

    /// The number this level is written as, for a front end that offers it as a
    /// dial rather than a word.
    pub const fn level(self) -> u8 {
        match self {
            ServiceDetection::Off => 0,
            ServiceDetection::Banner => 1,
            ServiceDetection::Probe => 2,
        }
    }

    /// The level with this number, or `None` past the highest there is.
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(ServiceDetection::Off),
            1 => Some(ServiceDetection::Banner),
            2 => Some(ServiceDetection::Probe),
            _ => None,
        }
    }

    /// Whether this level opens a connection at all.
    ///
    /// The boundary that matters to a target: below it the scan is invisible to
    /// every application log on the host, and at or above it every open port
    /// records a connection.
    ///
    /// ```
    /// use zond_engine::config::ServiceDetection;
    ///
    /// assert!(!ServiceDetection::Off.connects());
    /// assert!(ServiceDetection::default().connects());
    /// ```
    pub const fn connects(self) -> bool {
        !matches!(self, ServiceDetection::Off)
    }

    /// Whether this level sends anything once connected.
    ///
    /// ```
    /// use zond_engine::config::ServiceDetection;
    ///
    /// assert!(!ServiceDetection::Banner.sends());
    /// assert!(ServiceDetection::Probe.sends());
    /// ```
    pub const fn sends(self) -> bool {
        matches!(self, ServiceDetection::Probe)
    }
}

impl fmt::Display for ServiceDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error parsing a [`ServiceDetection`] returns, carrying the values that
/// would have worked so a front end can print it verbatim.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error(
    "unknown service detection level '{input}', expected one of: off, banner, probe \
     (or 0, 1, 2)"
)]
pub struct UnknownServiceDetection {
    /// What the caller wrote.
    pub input: String,
}

impl FromStr for ServiceDetection {
    type Err = UnknownServiceDetection;

    /// Parses a level by name or by number, on the same terms
    /// [`OsDetection`] does and for the same reason.
    ///
    /// ```
    /// use zond_engine::config::ServiceDetection;
    ///
    /// assert_eq!("banner".parse(), Ok(ServiceDetection::Banner));
    /// assert_eq!("0".parse(), Ok(ServiceDetection::Off));
    /// assert!("thorough".parse::<ServiceDetection>().is_err());
    /// ```
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let trimmed = input.trim();
        if let Ok(level) = trimmed.parse::<u8>()
            && let Some(detection) = Self::from_level(level)
        {
            return Ok(detection);
        }

        Self::ALL
            .into_iter()
            .find(|detection| detection.name().eq_ignore_ascii_case(trimmed))
            .ok_or_else(|| UnknownServiceDetection {
                input: input.to_string(),
            })
    }
}

/// User control over retransmission, applied on top of each scanner's own
/// profile.
///
/// Comparable so a report can state whether two runs were asked for the same
/// effort. Not [`Eq`]: `timeout_scale` is a float, and a scale nobody can write
/// down exactly is not a scale two runs should be claimed to share.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryConfig {
    pub effort: ScanEffort,
    /// Replaces the attempt budget outright, whatever `effort` implies. One
    /// disables retransmission.
    pub max_attempts: Option<u8>,
    /// Multiplies how long the scan is willing to wait.
    ///
    /// Deliberately does not touch the shortest timeout a policy allows. That
    /// floor is not a preference to be traded away, it is what the protocol
    /// costs: retrying a UDP probe sooner than the target is permitted to answer
    /// is not a faster scan, it is a wasted packet.
    pub timeout_scale: Option<f64>,
    /// Whether a host that answers nothing at all may have its budget cut.
    /// Turning this off spends the full budget on every port of every silent
    /// address, which is thorough and expensive.
    pub dampen_silent_hosts: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            effort: ScanEffort::default(),
            max_attempts: None,
            timeout_scale: None,
            dampen_silent_hosts: true,
        }
    }
}

/// The knobs a probing strategy is built from, carried together so adding one
/// does not mean threading another parameter through every constructor.
///
/// Not every strategy reads every field: local discovery builds its own
/// Ethernet frames and so has no use for [`SendMode`], while every strategy that
/// sends a probe at all has a use for [`RetryConfig`]. `max_probe_rate` is read
/// by routed host discovery and by the raw port scanners, and it means something
/// different to each — the sweep and the UDP scan are paced *by* it, while a TCP
/// port scan paces itself by a congestion window and treats it only as a
/// ceiling. The unprivileged paths pace themselves by their connection
/// concurrency instead.
#[derive(Debug, Clone, Default)]
pub struct ProbeTuning {
    pub send_mode: SendMode,
    pub retry: RetryConfig,
    pub max_probe_rate: Option<u32>,
    /// Which segment a TCP port probe carries. Read only by the raw TCP port
    /// scanner: host discovery asks whether anything is there, which every one
    /// of these techniques answers equally badly, so it stays on SYN.
    pub tcp_technique: TcpScanTechnique,

    /// How far a strategy may go to identify the operating system behind a host.
    ///
    /// Read by the raw TCP port scanner, which is where the replies that carry a
    /// stack's shape arrive. At [`OsDetection::Passive`] it changes no packet and
    /// no timing — it reads a reply the scan already drew — so it is here rather
    /// than in a phase of its own.
    pub os_detection: OsDetection,

    /// How far a strategy may go to name what is behind an open port.
    ///
    /// Read by every strategy that fingerprints: the raw scanners, which do it
    /// as a second pass over the ports they found, and the connect scanner,
    /// which does it inline over the connection it already holds. Both consult
    /// the same level, so turning it off means no connection is completed for
    /// identification by either route.
    pub service_detection: ServiceDetection,

    /// What the caller has chosen to change about the packets each strategy
    /// emits, over the defaults it would otherwise send.
    ///
    /// A default profile is inert: a strategy handed one sends exactly what it
    /// would without it. Read wherever a strategy chooses a field a caller may
    /// override — the source port a probe leaves from today, and the hop limit,
    /// spoofed address, fragmentation and decoys as those land. See
    /// [`EvasionProfile`].
    pub evasion: EvasionProfile,
}

/// A third party whose IP-ID counter an idle scan reads to learn a target's
/// ports without ever addressing the target as itself.
///
/// The idle (or zombie) scan is the quietest technique this engine has: it
/// forges its probes to carry the zombie's source address, so the target's
/// answers go to the zombie and never to the scanner. What the target said is
/// read indirectly, off the one thing the zombie's replies leak — a global
/// IP-ID counter that advances by one for every packet the zombie sends. Read
/// the counter, forge a probe, read it again: an open port drew an answer the
/// zombie had to reset, advancing the counter an extra step, and a closed or
/// filtered one did not.
///
/// It follows that the zombie has to be the right kind of host — one whose
/// IP-ID is a single shared counter — and that the forged probe needs a
/// self-built Ethernet frame to carry a source address the kernel would never
/// choose. A scan that cannot have either is refused rather than run quietly
/// wrong; see the idle port scanner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleScan {
    /// The zombie's address.
    ///
    /// It must be a host with a single global IP-ID counter — a *counting*
    /// generator, in the terms the OS-detection series reads — and idle and
    /// reachable enough that its counter moves for this scan's probes and little
    /// else. A busy zombie's own traffic is noise the scan has to see through,
    /// and one whose counter is random or per-connection carries no signal at
    /// all; both are caught when the scan qualifies it, and an unsuitable zombie
    /// is refused with the counter class it was found to have.
    pub zombie: IpAddr,

    /// A port on the zombie to probe for its counter, or `None` for the engine's
    /// default.
    ///
    /// Any port serves in principle — an unsolicited SYN/ACK draws a reset
    /// whether the port is open or closed, and it is the reset's IP-ID the scan
    /// reads — but the zombie's own filter must not drop the probe, so a caller
    /// that knows a port the zombie answers on can name it here.
    pub zombie_port: Option<u16>,
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
/// scan was run*. [`ScanSettings`](crate::scanner::report::ScanSettings) is derived
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

    /// Whether a port scan should take its targets on trust rather than probing
    /// them for liveness first.
    ///
    /// Off by default, so [`scan`](crate::scan) establishes that a target is
    /// there before spending a probe on each of its ports. An address nothing
    /// answers for otherwise comes back with every port filtered, which is a
    /// thousand lines of the scan reporting its own silence — and on a wide port
    /// range it is most of the run's cost.
    ///
    /// Set it when the liveness probe is the thing that is wrong: a host behind
    /// a firewall that drops ICMP and answers nothing on the discovery ports is
    /// reported down and never scanned, and it may well be up. That is the
    /// trade — the check is what stops a dead address costing a full scan, and
    /// turning it off is what reaches a host that will not answer a knock.
    ///
    /// The liveness phase probes the addresses it was given and nothing else. It
    /// is not a segment sweep; see [`segment_sweep`](Self::segment_sweep).
    pub assume_up: bool,

    /// Whether to measure the route to each host that answered.
    ///
    /// Off by default, and it is the one detection setting that is off for a
    /// reason other than traffic volume. A trace costs roughly one probe per
    /// router per host and tells you nothing about the host itself: it is a
    /// finding about the network in between, which is a different question from
    /// the one a port scan was asked. Somebody mapping a network wants it and
    /// somebody auditing a server does not, and neither should pay for the
    /// other's answer.
    ///
    /// **Only hosts that answered something are traced.** A path is measured
    /// backwards from the target, which needs the target's distance, which is
    /// read out of a reply it sent — so a host that answered nothing has no
    /// path this engine can measure and is skipped rather than probed thirty
    /// times for nothing. See
    /// [`traceroute`](crate::scanner::strategy::routed::traceroute).
    ///
    /// Needs raw sockets, like every other probe this engine builds by hand. An
    /// unprivileged run records the refusal rather than reporting an empty path,
    /// which would read as a network with no routers in it.
    pub traceroute: bool,

    /// Whether to characterise the filter in front of each host that answered.
    ///
    /// Off by default, and off for the same reason a traceroute is: it costs a
    /// handful of extra probes per live host and answers a different question
    /// from the one a port scan was asked — what the filtering *between* the
    /// scanner and a host is doing, rather than what the host runs. A firewall
    /// tester wants it; an inventory scan does not.
    ///
    /// A pass of its own, run after the ports are known and only against hosts
    /// that answered, sending deliberately-shaped diagnostic probes whose results
    /// it reads as [`Filtering`](crate::model::host::Filtering) conclusions. It
    /// does not touch the port verdicts — a bad-checksum probe, the one it sends
    /// today, would report every port filtered if it were the setting a scan ran
    /// under, which is exactly why it is a separate pass and not a scan option.
    pub characterise: bool,

    /// Scan TCP ports through a third-party zombie rather than by addressing the
    /// target directly, when set. See [`IdleScan`].
    ///
    /// This replaces the ordinary TCP port scan wholesale: the technique in
    /// [`tcp_technique`](Self::tcp_technique) does not apply, because every probe
    /// is a forged SYN read through the zombie's counter rather than a segment
    /// whose own reply is classified. It is TCP-only — a UDP port cannot be read
    /// this way, and probing one directly would announce the scanner the idle
    /// technique exists to hide, so UDP targets are left unprobed. It needs the
    /// privilege and the self-built frame a spoofed source address requires, and
    /// a suitable zombie; lacking any of these the scan is refused, never run
    /// under its own address instead.
    pub idle_scan: Option<IdleScan>,

    /// Addresses this scan may not probe, whatever else it was asked to cover.
    ///
    /// Empty by default. Everything else in this struct decides *how* a scan is
    /// run; this is the only field that decides where it may not go, and it is
    /// the only one whose failure to be honoured is somebody's contract rather
    /// than somebody's result. An engagement scoped as "10.0.0.0/8, except the
    /// cardholder segment" has no other way to be expressed, and a scanner that
    /// cannot express it cannot be pointed at that network at all.
    ///
    /// It is enforced twice, before the first packet and again at every finding,
    /// and the reasons for both are in [`Exclusions`]. Read that before changing
    /// anything here: the second enforcement exists because a segment sweep
    /// learns addresses that were never in the target list, and losing it turns
    /// a guarantee back into a filter.
    ///
    /// **Narrowing only.** No value here can make a scan send a packet it would
    /// not otherwise have sent, which is what makes it safe to accept from a
    /// settings file when [`segment_sweep`](Self::segment_sweep) is not — see
    /// `import::settings::Settings`, where that asymmetry is the whole
    /// argument for which keys a document is allowed to carry.
    pub exclusions: Exclusions,

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
    /// [`ScanSettings`](crate::scanner::report::ScanSettings) and the export layer's
    /// own [`Redaction`](crate::export::Redaction) policy. Masking on the way out
    /// rather than on the way in is deliberate: the alternative is a report that
    /// has quietly lost data nobody can recover.
    pub redact: bool,

    /// How raw SYN probes are placed on the wire. Defaults to
    /// [`SendMode::Auto`], which is correct on every supported platform;
    /// override it only to force Layer-2 sends for host-stack-bypass scanning.
    pub send_mode: SendMode,

    /// The fastest a scan may put probes on the wire, in probes per second.
    /// `None` leaves each scanner's own default in force.
    ///
    /// This is a coverage control before it is a politeness one. A probe's
    /// chance of being answered falls as the rate rises: on a policed path a
    /// burst loses most of its first attempt and the loss is recovered, if at
    /// all, by retransmitting into a quieter moment. Lowering the rate buys
    /// coverage on the first attempt instead, and raising it trades coverage
    /// for the time a large range takes to emit.
    ///
    /// **It is a ceiling on a TCP port scan rather than its pace.** That scan
    /// discovers how fast each target will answer and settles there, which is
    /// almost always well below any rate worth configuring; see
    /// [`congestion`](crate::scanner::pacing::congestion). Setting this lowers
    /// the ceiling the window may reach and is the right knob for a target that
    /// must not be pushed at all, but on an ordinary scan it will not be what
    /// decides the pace. The discovery sweep and the UDP port scan *are* paced
    /// by it, because neither is given evidence it could adapt on.
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
    /// [`ScanEffort::Balanced`].
    pub retry: RetryConfig,

    /// How far the scan goes to identify the operating system behind each host.
    ///
    /// Defaults to [`OsDetection::Passive`], which reads what the replies the
    /// scan already drew happen to say and emits nothing of its own. The higher
    /// levels send probes and have to be asked for; see [`OsDetection`] for what
    /// each one puts on the wire.
    pub os_detection: OsDetection,

    /// How far the scan goes to identify what is listening behind each open
    /// port.
    ///
    /// Defaults to [`ServiceDetection::Probe`], which connects to every open
    /// port and asks it what it is. That is the level worth having — a port
    /// state without a service name answers half the question — but it is also
    /// the one that completes connections, so a scan that must stay out of the
    /// target's application logs turns it off. Affects the port-scan phase only.
    pub service_detection: ServiceDetection,

    /// How intrusive a detection the scan may run against an identified service.
    ///
    /// After service detection names a port, the flow corpus can probe it further
    /// to conclude what is *wrong* with it, not just what it is. This is the
    /// ceiling on how far that goes: the default permits passive and active-benign
    /// detections, and a detection that mutates, exploits, or degrades the target
    /// runs only where the operator raises the ceiling to it. Read by the
    /// detection phase, after service detection, and only when it ran.
    pub detection: DetectionEnvelope,

    /// What the scan changes about the packets it emits, over the defaults.
    ///
    /// Defaults to an inert profile — a scan that set nothing here is
    /// indistinguishable from one run before the option existed. Carried into
    /// [`probe_tuning`](Self::probe_tuning) for the strategies to read, and (once
    /// the provenance surface lands) into the report, so a scan that evaded
    /// something says so. See [`EvasionProfile`].
    pub evasion: EvasionProfile,
}

impl ZondConfig {
    /// The probe-level knobs, bundled for the strategies that need them.
    pub fn probe_tuning(&self) -> ProbeTuning {
        ProbeTuning {
            send_mode: self.send_mode,
            retry: self.retry,
            max_probe_rate: self.max_probe_rate,
            tcp_technique: self.tcp_technique,
            os_detection: self.os_detection,
            service_detection: self.service_detection,
            evasion: self.evasion.clone(),
        }
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

    /// A level's number is written down in three places — the position in
    /// [`OsDetection::ALL`], the arm in `level`, and the arm in `from_level` —
    /// and a fifth level added to two of them would leave a name and a number
    /// that quietly disagree. Nothing else would notice: both spellings would
    /// still parse, and a front end offering the dial would simply select the
    /// wrong thing.
    #[test]
    fn every_os_detection_level_agrees_with_its_number() {
        for (index, detection) in OsDetection::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(detection.level()), index);
            assert_eq!(OsDetection::from_level(detection.level()), Some(detection));
        }

        let past_the_end = OsDetection::ALL.len() as u8;
        assert_eq!(
            OsDetection::from_level(past_the_end),
            None,
            "a level this engine does not offer is refused, not rounded down to the highest"
        );
    }

    /// A level's number is written down in three places, exactly as
    /// [`OsDetection`]'s is, and the same silent disagreement is possible.
    #[test]
    fn every_service_detection_level_agrees_with_its_number() {
        for (index, detection) in ServiceDetection::ALL.into_iter().enumerate() {
            assert_eq!(usize::from(detection.level()), index);
            assert_eq!(
                ServiceDetection::from_level(detection.level()),
                Some(detection)
            );
        }

        let past_the_end = ServiceDetection::ALL.len() as u8;
        assert_eq!(ServiceDetection::from_level(past_the_end), None);
    }

    /// The two boundaries that matter to a target, and they are different ones.
    ///
    /// `connects` is what its application logs would record; `sends` is what its
    /// services would be handed. A level that connected but sent nothing, and a
    /// level that did neither, look identical in every count a scan reports and
    /// could hardly be more different to whoever runs the machine.
    #[test]
    fn each_service_detection_level_says_what_it_puts_on_the_wire() {
        assert!(!ServiceDetection::Off.connects());
        assert!(!ServiceDetection::Off.sends());

        assert!(ServiceDetection::Banner.connects());
        assert!(
            !ServiceDetection::Banner.sends(),
            "listening is the whole of what this level does"
        );

        assert!(ServiceDetection::Probe.connects());
        assert!(ServiceDetection::Probe.sends());

        assert!(
            ServiceDetection::default().sends(),
            "the default asks, because asking is both the informative answer and \
             the fast one"
        );
    }

    /// Both spellings are one setting, on the same reasoning [`OsDetection`]
    /// accepts both.
    #[test]
    fn a_service_detection_level_parses_the_same_by_name_and_by_number() {
        for detection in ServiceDetection::ALL {
            assert_eq!(detection.name().parse(), Ok(detection));
            assert_eq!(detection.level().to_string().parse(), Ok(detection));
        }

        assert!("3".parse::<ServiceDetection>().is_err());
        assert!("thorough".parse::<ServiceDetection>().is_err());
    }

    /// Where the wire cost begins. The default level promises to emit nothing at
    /// all, and that promise is what makes it safe to leave on for every scan —
    /// so which levels answer `true` here is a behavioural contract, not an
    /// implementation detail.
    #[test]
    fn os_detection_sends_nothing_below_the_active_level() {
        assert!(!OsDetection::Off.is_active());
        assert!(!OsDetection::Passive.is_active());
        assert!(OsDetection::Active.is_active());
        assert!(OsDetection::Aggressive.is_active());

        assert!(!OsDetection::default().is_active(), "the default is silent");
        assert!(OsDetection::default().is_enabled(), "and it is still on");
    }

    /// The two spellings are one setting, so a name and its number have to parse
    /// to the same level. A front end reading `2` from a flag and `active` from a
    /// settings file must not get two different scans.
    #[test]
    fn an_os_detection_level_parses_the_same_by_name_and_by_number() {
        for detection in OsDetection::ALL {
            assert_eq!(detection.name().parse(), Ok(detection));
            assert_eq!(detection.level().to_string().parse(), Ok(detection));
        }

        assert!("4".parse::<OsDetection>().is_err());
        assert!("passive-ish".parse::<OsDetection>().is_err());
    }
}
