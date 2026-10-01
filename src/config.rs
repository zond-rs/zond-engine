// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What a scan is asked to do
//!
//! [`ZondConfig`] is one value, built once, handed to [`scan`](crate::scanner::scan) or
//! [`discover`](crate::scanner::discover), and read by every strategy the run assembles.
//! The default sends what a scan must and no more.
//!
//! ## Effort levels
//!
//! Most of what a person wants to say about a scan is how hard it should try.
//! [`ScanEffort`] sets how many attempts a probe gets and how long each waits.
//! [`OsDetection`] and [`ServiceDetection`] set how far a run may go to name what it
//! found.
//!
//! [`ScanPace`] is a preset over them: one dial for how gently a scan treats the network.
//! It writes the gaps between probes and the patience into the other fields and is not
//! read by anything itself, so a scan always runs under the fields, and a setting chosen
//! after the pace replaces what the pace wrote.
//!
//! All four are built alike: an ordered scale, an `ALL` in that order, a `name` and a
//! `level` for each rung, and a `FromStr` that takes either spelling, so a front end can
//! accept a word from a settings file and a number from a flag. The first three are
//! carried into the report; a pace is carried as the fields it wrote.
//!
//! [`ScanEffort`] and [`OsDetection`] default low, since effort and traffic are what a
//! caller should have to ask for. [`ServiceDetection`] defaults to its top level, which is
//! also its fastest against an unrecognised port; the reasoning is at the variant.
//!
//! The numbers a strategy actually paces by are not set here. A raw scanner measures its
//! own round trips and sizes its patience from them; the connect paths, which cannot
//! measure, use the shared constants in [`limits`]. A caller supplies a ceiling and a
//! preference, and the engine decides the rest against the network in front of it.
//!
//! ## Evasion and permission
//!
//! [`EvasionProfile`] changes the shape of what goes on the wire, and is inert by
//! default: a strategy handed a default profile sends exactly what it would without one.
//!
//! [`DetectionEnvelope`] is a permission. A detection declares how intrusive it is and
//! runs only where the envelope allows that class, so raising it is an operator's
//! decision. See [`envelope`] for the ordering.
//!
//! ## Output is not configured here
//!
//! The engine emits `tracing` events and installs no subscriber, so verbosity, colour
//! and format belong to whoever embeds the crate. This type is also the record of how a
//! scan was run ([`ScanSettings`](crate::report::ScanSettings) is derived from it into
//! every report), so it holds only fields that can change a finding.

pub mod envelope;
pub mod limits;

pub use crate::config::envelope::DetectionEnvelope;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;
use std::num::{NonZeroU8, NonZeroU32};
use std::str::FromStr;
use std::time::Duration;

use crate::evasion::EvasionProfile;
use crate::model::exclusion::Exclusions;
use crate::model::technique::{SctpScanTechnique, TcpScanTechnique};
use crate::transport::probe::SendMode;

/// Reads a level written as its name or as its number, shared by every scale in this
/// module. A settings file says `passive` and a command line says `2`; parsing both here
/// keeps the correspondence in one place.
fn parse_level<T: Copy>(
    written: &str,
    all: &[T],
    name: fn(T) -> &'static str,
    from_level: fn(u8) -> Option<T>,
) -> Option<T> {
    let written = written.trim();

    if let Ok(level) = written.parse::<u8>() {
        return from_level(level);
    }

    all.iter()
        .copied()
        .find(|level| name(*level).eq_ignore_ascii_case(written))
}

/// The `expected one of` half of every parse error in this module, built from the
/// levels themselves so a new variant is named without editing the message.
fn expected_levels<T: Copy>(
    all: &[T],
    name: fn(T) -> &'static str,
    f: &mut fmt::Formatter<'_>,
) -> fmt::Result {
    let names: Vec<&str> = all.iter().copied().map(name).collect();
    let highest = all.len().saturating_sub(1);
    write!(
        f,
        "expected one of: {} (or 0 to {highest})",
        names.join(", ")
    )
}

/// How much effort a scan spends before accepting silence as an answer.
///
/// Every probing path has its own `RetryPolicy`, tuned to what its protocol requires: a
/// SYN is answered as fast as the path allows, an ICMP error only as fast as the host is
/// permitted to send one. This scales that starting point, so choosing "fast" cannot hand
/// the UDP scanner a schedule its protocol cannot satisfy.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScanEffort {
    /// One probe per target and no repeats.
    ///
    /// For address-space-scale sweeps, where per-probe state cannot be afforded and
    /// coverage comes from a second pass.
    Single,
    /// Fewer attempts and less patience. For a network already known to be
    /// healthy, where a missed host is cheaper than the time spent confirming
    /// one is absent.
    Fast,
    /// The default. Enough attempts to ride out ordinary loss, and enough patience for
    /// a host on the far side of a slow link.
    #[default]
    Balanced,
    /// More attempts, more patience, and no shortcuts on hosts that stay
    /// silent. For a lossy path, or a result someone is going to act on.
    Thorough,
}

impl ScanEffort {
    /// Every level, ordered from least effort to most. The index of a level in
    /// this array is its [`level`](Self::level) number.
    pub const ALL: &'static [Self] = &[
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

    /// The number this level is written as, for a front end that offers it as a dial.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::ScanEffort;
    ///
    /// assert_eq!(ScanEffort::default().level(), 2);
    /// ```
    pub const fn level(self) -> u8 {
        match self {
            ScanEffort::Single => 0,
            ScanEffort::Fast => 1,
            ScanEffort::Balanced => 2,
            ScanEffort::Thorough => 3,
        }
    }

    /// The level with this number, or `None` past the highest there is. Not
    /// saturating, for the reason [`OsDetection::from_level`] gives.
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(ScanEffort::Single),
            1 => Some(ScanEffort::Fast),
            2 => Some(ScanEffort::Balanced),
            3 => Some(ScanEffort::Thorough),
            _ => None,
        }
    }
}

impl std::fmt::Display for ScanEffort {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The error parsing a [`ScanEffort`] returns. Its message lists the accepted names,
/// built from [`ScanEffort::ALL`], so a front end can print it verbatim.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownScanEffort {
    /// What the caller wrote.
    pub input: String,
}

impl fmt::Display for UnknownScanEffort {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown scan effort '{}', ", self.input)?;
        expected_levels(ScanEffort::ALL, ScanEffort::name, f)
    }
}

impl std::error::Error for UnknownScanEffort {}

impl std::str::FromStr for ScanEffort {
    type Err = UnknownScanEffort;

    /// Parses an effort by name or number, ignoring case and surrounding whitespace.
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
        parse_level(s, Self::ALL, Self::name, Self::from_level).ok_or_else(|| UnknownScanEffort {
            input: s.to_string(),
        })
    }
}

/// How far a scan goes to identify the operating system behind a host.
///
/// Four levels, ordered by what they put on the wire. Each is a superset of the one
/// below, so raising the level only adds evidence, and
/// [`is_active`](Self::is_active) (whether a level may send packets of its own) has a
/// single answer.
///
/// # Why the default is on
///
/// [`Passive`](Self::Passive) sends **nothing**. Every signal it reads is already in a
/// reply the scan drew for another reason: the hop count, fragmentation policy and
/// identifier in an IP header, and the window and options of a segment the port scanner
/// was waiting for anyway. Traffic and run time are byte-for-byte the same with it on or
/// off, so there is nothing to weigh.
///
/// [`Off`](Self::Off) is for a caller who wants a report to contain only what was asked
/// for, or to reproduce a run made without OS detection.
///
/// # Why the higher levels are not
///
/// From [`Active`](Self::Active) upward this costs packets. They are ordinary (a SYN
/// identical to the one a port scan sends, and a ping), but they are extra: a host is
/// asked several more times than classifying its ports required, at addresses a caller
/// may only have meant to enumerate. Traffic sent for a second purpose has to be asked
/// for.
///
/// [`Aggressive`](Self::Aggressive) is where deliberately malformed probes would belong,
/// the traffic intrusion-detection systems are written to notice. No level sends one
/// yet; each level is documented for what it does.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OsDetection {
    /// Level 0. Identify nothing, and record nothing about the stacks that
    /// answered.
    Off,

    /// Level 1, and the default. Read the operating system out of replies the
    /// scan already drew, and send nothing extra.
    ///
    /// Answers at the level of a family (the shape of a stack, not its version), and
    /// only for hosts that replied to something.
    #[default]
    Passive,

    /// Level 2. Everything [`Passive`](Self::Passive) reads, plus probes of this
    /// engine's own aimed at the hosts whose replies were not enough.
    ///
    /// Ordinary, well-formed packets, with no flag combination a real connection
    /// lacks:
    ///
    /// - **A series of SYNs**, to a host with an open or closed TCP port. The same
    ///   segment a SYN scan sends, from a fresh source port each time, because whether
    ///   a stack's IP identifier counts or is random, whether its sequence numbers are
    ///   hashed or stepped, and how fast its timestamp clock ticks show only across
    ///   several replies. Release-level rules turn on these features.
    /// - **One SNMP request**, to a host whose kernel is still unknown. On a Unix host
    ///   `sysDescr` is the output of `uname -a`, so an agent that answers states the
    ///   exact kernel, which packet analysis cannot establish and a
    ///   known-vulnerability lookup keys on. Sent with the default `public` community,
    ///   read-only, for one object.
    /// - **One ICMP echo**, to a host that answered no TCP probe. A stock Windows
    ///   firewall drops TCP silently, so a desktop with nothing exposed emits no
    ///   segment to read; a ping is the one packet it still answers.
    ///
    /// None of them touches the port list, so no probe goes to a port the caller
    /// excluded. The probes go only to hosts where the passive evidence was thin.
    Active,

    /// Level 3. The same probes [`Active`](Self::Active) sends, more of them, and at
    /// every host, including those already identified.
    ///
    /// Twice the samples per host, and hosts already named with high confidence are
    /// probed too. That suits someone measuring: a reading from a machine whose
    /// operating system is known is how a rule gets authored. It is more traffic,
    /// sustained longer, at more addresses.
    ///
    /// # Malformed probes
    ///
    /// This level sends none yet. Reserved fields set, impossible flag combinations and
    /// headers that disagree with their own lengths separate stacks that agree on
    /// everything legal, but rules are authored from what this engine's own probes have
    /// measured, and nothing has measured those. If they are added, they go here.
    Aggressive,
}

impl OsDetection {
    /// Every level, ordered from least effort to most. The index of a level in
    /// this array is its [`level`](Self::level) number.
    pub const ALL: &'static [Self] = &[
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

    /// The number this level is written as, for a front end that offers it as a dial.
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
    /// Not saturating: a caller who writes `9` meaning "as much as possible" has asked
    /// for something this engine does not offer, and quietly giving them the top level
    /// would hide that.
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
    /// A scan that must add no traffic of its own, and a report that has to say whether
    /// it did, both turn on this.
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

/// The error parsing an [`OsDetection`] returns. Its message lists the accepted values,
/// built from [`OsDetection::ALL`], so a front end can print it verbatim.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownOsDetection {
    /// What the caller wrote.
    pub input: String,
}

impl fmt::Display for UnknownOsDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown OS detection level '{}', ", self.input)?;
        expected_levels(OsDetection::ALL, OsDetection::name, f)
    }
}

impl std::error::Error for UnknownOsDetection {}

impl FromStr for OsDetection {
    type Err = UnknownOsDetection;

    /// Parses a level by name or by number, ignoring case and surrounding whitespace.
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
        parse_level(s, Self::ALL, Self::name, Self::from_level).ok_or_else(|| UnknownOsDetection {
            input: s.to_string(),
        })
    }
}

/// The TCP ports a network printer prints whatever arrives on: 9100 for its
/// first queue and 9101 to 9107 for the rest.
///
/// Raw printing (JetDirect, AppSocket) has no protocol: every byte a connection carries
/// is printed. The default for [`ZondConfig::listen_only_ports`].
pub const RAW_PRINT_PORTS: &[u16] = &[9100, 9101, 9102, 9103, 9104, 9105, 9106, 9107];

/// How far a scan may go to identify what is listening behind an open port.
///
/// The port scan establishes that a port is *open*; naming what is on it is a second
/// pass that needs a real connection to every open port. A scan mapping what exists may
/// not want that cost; a scan auditing what is deployed does.
///
/// Ordered by what each level puts on the wire.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ServiceDetection {
    /// Level 0. Do not connect. A port keeps whatever its number implies and
    /// nothing more.
    ///
    /// The fastest and quietest: after a raw scan no connection is completed, so
    /// nothing appears in the target's logs. It yields no versions or products: a port
    /// is reported `open http` because it is port 80, whatever is actually there.
    Off,
    /// Level 1. Connect and listen. Send nothing.
    ///
    /// For services that greet on connect, such as SSH, SMTP, FTP and IRC, this learns
    /// what a probe would, without sending a byte. For everything else it establishes
    /// only that the port accepts connections.
    ///
    /// Use it against equipment that must not be sent anything unexpected. Industrial
    /// controllers, medical devices and old embedded stacks have been knocked over by
    /// well-formed requests they did not anticipate.
    Banner,
    /// Level 2, and the default. Connect, listen, and ask.
    ///
    /// Sends each port the probes its service registered and, where nothing registers
    /// the port, one generic request. That identifies the long tail: an open port on an
    /// unregistered number is most often an HTTP server, and one request names it.
    ///
    /// A port that answers none of that, in the clear or through TLS, is then asked
    /// the likeliest of the questions other services registered, the bottom of the
    /// scale [`probe_intensity`](Self::probe_intensity) reaches. Such a port is most
    /// often a database moved off its number, which speaks only when spoken to in its
    /// own protocol. Each question costs a connection and a read. Across a path slower
    /// than a third of a second only the likeliest is asked.
    ///
    /// The default because it is the most informative level and, against an
    /// unrecognised port, the fastest: waiting for a greeting that never comes and then
    /// trying TLS costs two seconds per port, where asking gets an answer in a round
    /// trip.
    #[default]
    Probe,
    /// Level 3. Everything above, and then every question the corpus has.
    ///
    /// A port that stayed silent through everything else gets every probe authored for
    /// *other* services, in rarity order. That reaches a service which speaks only when
    /// spoken to, is off its registered port, and is rarer than the default's guesses.
    ///
    /// Costs a connection and a round trip per probe, paid only where everything else
    /// drew a blank, which on an ordinary host is a port or two.
    Thorough,
}

impl ServiceDetection {
    /// Every level, ordered from least effort to most. The index of a level in
    /// this array is its [`level`](Self::level) number.
    pub const ALL: &'static [Self] = &[
        ServiceDetection::Off,
        ServiceDetection::Banner,
        ServiceDetection::Probe,
        ServiceDetection::Thorough,
    ];

    /// The name this level is written under, wherever it arrives as text.
    pub const fn name(self) -> &'static str {
        match self {
            ServiceDetection::Off => "off",
            ServiceDetection::Banner => "banner",
            ServiceDetection::Probe => "probe",
            ServiceDetection::Thorough => "thorough",
        }
    }

    /// The number this level is written as, for a front end that offers it as a dial.
    pub const fn level(self) -> u8 {
        match self {
            ServiceDetection::Off => 0,
            ServiceDetection::Banner => 1,
            ServiceDetection::Probe => 2,
            ServiceDetection::Thorough => 3,
        }
    }

    /// The level with this number, or `None` past the highest there is.
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(ServiceDetection::Off),
            1 => Some(ServiceDetection::Banner),
            2 => Some(ServiceDetection::Probe),
            3 => Some(ServiceDetection::Thorough),
            _ => None,
        }
    }

    /// Whether this level opens a connection at all.
    ///
    /// Below this boundary the scan leaves no trace in application logs; at or above
    /// it every open port records a connection.
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
        matches!(self, ServiceDetection::Probe | ServiceDetection::Thorough)
    }

    /// How far up the corpus's rarity scale this level reaches, for a probe
    /// nothing registered against the port being asked.
    ///
    /// The scale runs 1 to 9 and is the one the imported corpora are authored
    /// on; see [`Probe::rarity`](crate::fingerprint::Probe::rarity). Zero
    /// reaches nothing, which is what every level below [`Probe`] wants.
    ///
    /// The default reaches 1, the questions a port silent to everything else most
    /// often answers, and the thorough level the whole scale. The default stops at 1
    /// because only the bottom of the scale is authored so far; it can rise as the
    /// corpus fills in.
    ///
    /// ```
    /// use zond_engine::config::ServiceDetection;
    ///
    /// assert_eq!(ServiceDetection::Banner.probe_intensity(), 0);
    /// assert_eq!(ServiceDetection::Thorough.probe_intensity(), 9);
    /// ```
    ///
    /// [`Probe`]: Self::Probe
    pub const fn probe_intensity(self) -> u8 {
        match self {
            ServiceDetection::Off | ServiceDetection::Banner => 0,
            ServiceDetection::Probe => 1,
            ServiceDetection::Thorough => 9,
        }
    }
}

impl fmt::Display for ServiceDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error parsing a [`ServiceDetection`] returns. Its message lists the accepted
/// values, built from [`ServiceDetection::ALL`], so a front end can print it verbatim.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownServiceDetection {
    /// What the caller wrote.
    pub input: String,
}

impl fmt::Display for UnknownServiceDetection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown service detection level '{}', ", self.input)?;
        expected_levels(ServiceDetection::ALL, ServiceDetection::name, f)
    }
}

impl std::error::Error for UnknownServiceDetection {}

impl FromStr for ServiceDetection {
    type Err = UnknownServiceDetection;

    /// Parses a level by name or by number, ignoring case and surrounding whitespace.
    ///
    /// ```
    /// use zond_engine::config::ServiceDetection;
    ///
    /// assert_eq!("banner".parse(), Ok(ServiceDetection::Banner));
    /// assert_eq!("0".parse(), Ok(ServiceDetection::Off));
    /// assert_eq!("3".parse(), Ok(ServiceDetection::Thorough));
    /// assert!("exhaustive".parse::<ServiceDetection>().is_err());
    /// ```
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_level(input, Self::ALL, Self::name, Self::from_level).ok_or_else(|| {
            UnknownServiceDetection {
                input: input.to_string(),
            }
        })
    }
}

/// How gently a scan treats the network it is pointed at, as one dial.
///
/// A preset over several settings, for a caller who knows how much load a network can
/// take but not which knobs express that. [`apply_to`](Self::apply_to) writes the pace
/// into a [`ZondConfig`]; nothing downstream reads a pace, so a scan runs under (and the
/// report records) the fields it set. An explicit setting applied afterwards replaces
/// what the pace wrote.
///
/// # What the levels change
///
/// [`Normal`](Self::Normal) changes nothing, so a caller who picks it gets
/// exactly [`ZondConfig::default`]. Below it the pace spaces the scan's probes;
/// above it the pace shortens how long the scan waits for answers.
///
/// | Level | Name | Writes |
/// |---|---|---|
/// | 0 | `trickle` | one probe a second, across the scan and at any one host; twice the patience |
/// | 1 | `sparing` | ten probes a second, across the scan and at any one host; half again the patience |
/// | 2 | `gentle` | two hundred a second across the scan, twenty at any one host |
/// | 3 | `normal` | nothing |
/// | 4 | `brisk` | [`ScanEffort::Fast`] |
/// | 5 | `hurried` | [`ScanEffort::Fast`], and half that patience again |
///
/// The slow levels space probes with [`probe_interval`](ZondConfig::probe_interval) and
/// [`host_probe_interval`](ZondConfig::host_probe_interval), the bound every pass
/// shares. They leave [`max_probe_rate`](ZondConfig::max_probe_rate) alone: a rate
/// replaces each scanner's own default, so a rate gentle for a TCP scan would be
/// *faster* than the UDP scan's own pace.
///
/// Every slow level sets a per-host gap; the two slowest set it equal to the scan-wide
/// one. That keeps each host spared if a caller later loosens the scan-wide gap for a
/// range too large to cover at it.
///
/// The slow levels also raise the patience, which at their spacing costs nothing: each
/// probe waits out the gap anyway, and a longer timeout inside that wait catches late
/// answers from slow devices.
///
/// # The fast levels
///
/// They do not push harder. A TCP port scan paces itself on how fast its targets answer,
/// through a congestion window no setting overrides, because pushing a target harder than
/// it answers turns loss into verdicts. The fast levels trade patience (fewer attempts,
/// shorter waits) for time, which works on a network that answers promptly and poorly on
/// one that does not. [`hurried`](Self::Hurried) never goes below the shortest wait a
/// protocol allows; see [`TimeoutScale`].
///
/// # Cost
///
/// The slow levels leave out the operating-system timestamp series, whose samples
/// cannot be taken slower than they are sent; see
/// [`probe_interval`](ZondConfig::probe_interval).
///
/// A spaced scan takes as long as its probes take to leave: a thousand ports at
/// `sparing` is a hundred seconds before any retry, and at `trickle` a quarter of an
/// hour. Setting [`scan_timeout`](ZondConfig::scan_timeout) alongside a slow level
/// bounds that, and the report says which hosts the budget left part-scanned.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScanPace {
    /// Level 0. One probe a second across the whole scan, and twice the usual
    /// patience for each.
    ///
    /// For a network that must barely notice the scan: a link a few kilobits wide,
    /// equipment known to fall over under sustained traffic, or an owner who asked
    /// for less than a packet a second.
    Trickle,
    /// Level 1. Ten probes a second across the whole scan, and half again the
    /// usual patience for each.
    ///
    /// For a network whose owner wants the scan well below anything its monitoring
    /// would call load, and who can wait minutes for a host's ports.
    Sparing,
    /// Level 2. At most two hundred probes a second across the whole scan, and
    /// twenty a second at any one host.
    ///
    /// For a network with fragile hosts on it: a controller, a printer or an old
    /// embedded stack that copes with a scan but not a burst. The per-host bound spares
    /// them on a range scan, where the scan-wide one alone would still allow a burst at
    /// one host.
    Gentle,
    /// Level 3, and the default. Every setting as it is; each pass paces
    /// itself as it would with no pace chosen.
    #[default]
    Normal,
    /// Level 4. [`ScanEffort::Fast`]: an attempt fewer and less patience per
    /// probe.
    ///
    /// For a network known to be healthy, where a missed port is cheaper than the time
    /// spent confirming its silence.
    Brisk,
    /// Level 5. [`ScanEffort::Fast`], with each wait halved again.
    ///
    /// For a quick look at a network that answers promptly. Anything slow to answer is
    /// reported as silent, so a result is a first look, not a verdict.
    Hurried,
}

impl ScanPace {
    /// Every level, ordered from gentlest to fastest. The index of a level in
    /// this array is its [`level`](Self::level) number.
    pub const ALL: &'static [Self] = &[
        ScanPace::Trickle,
        ScanPace::Sparing,
        ScanPace::Gentle,
        ScanPace::Normal,
        ScanPace::Brisk,
        ScanPace::Hurried,
    ];

    /// The name this level is written under, wherever it arrives as text.
    pub const fn name(self) -> &'static str {
        match self {
            ScanPace::Trickle => "trickle",
            ScanPace::Sparing => "sparing",
            ScanPace::Gentle => "gentle",
            ScanPace::Normal => "normal",
            ScanPace::Brisk => "brisk",
            ScanPace::Hurried => "hurried",
        }
    }

    /// The number this level is written as, for a front end that offers it as a dial.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::ScanPace;
    ///
    /// assert_eq!(ScanPace::default().level(), 3);
    /// ```
    pub const fn level(self) -> u8 {
        match self {
            ScanPace::Trickle => 0,
            ScanPace::Sparing => 1,
            ScanPace::Gentle => 2,
            ScanPace::Normal => 3,
            ScanPace::Brisk => 4,
            ScanPace::Hurried => 5,
        }
    }

    /// The level with this number, or `None` past the highest there is. Not
    /// saturating, for the reason [`OsDetection::from_level`] gives.
    pub const fn from_level(level: u8) -> Option<Self> {
        match level {
            0 => Some(ScanPace::Trickle),
            1 => Some(ScanPace::Sparing),
            2 => Some(ScanPace::Gentle),
            3 => Some(ScanPace::Normal),
            4 => Some(ScanPace::Brisk),
            5 => Some(ScanPace::Hurried),
            _ => None,
        }
    }

    /// Writes this pace into `config`, leaving every field it has no view on
    /// as it was.
    ///
    /// Apply it before anything the caller set explicitly, which then replaces what the
    /// pace wrote.
    ///
    /// A slow level never loosens what `config` already holds: it takes the longer of
    /// its own gap and one already set, and the larger of the two patiences. A fast
    /// level sets effort and patience outright and touches no gap or rate.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use zond_engine::config::{ScanPace, ZondConfig};
    ///
    /// let mut cfg = ZondConfig::default();
    /// ScanPace::Sparing.apply_to(&mut cfg);
    /// assert_eq!(cfg.probe_interval, Some(Duration::from_millis(100)));
    ///
    /// // An explicit setting applied afterwards is the one that holds.
    /// cfg.probe_interval = Some(Duration::from_millis(250));
    /// ```
    pub fn apply_to(self, config: &mut ZondConfig) {
        let Some(spacing) = self.spacing() else {
            match self {
                ScanPace::Brisk => config.retry.effort = ScanEffort::Fast,
                ScanPace::Hurried => {
                    config.retry.effort = ScanEffort::Fast;
                    config.retry.timeout_scale = TimeoutScale::new(HURRIED_PATIENCE);
                }
                _ => {}
            }
            return;
        };

        config.probe_interval = config.probe_interval.max(Some(spacing.anywhere));
        config.host_probe_interval = config.host_probe_interval.max(Some(spacing.at_host));
        if let Some(patience) = spacing.patience {
            config.retry.timeout_scale = match config.retry.timeout_scale {
                Some(set) if set >= patience => Some(set),
                _ => Some(patience),
            };
        }
    }

    /// What a slow level writes, or `None` for a level that spaces nothing.
    fn spacing(self) -> Option<PaceSpacing> {
        let patience = |factor| TimeoutScale::new(factor);
        match self {
            ScanPace::Trickle => Some(PaceSpacing {
                anywhere: Duration::from_secs(1),
                at_host: Duration::from_secs(1),
                patience: patience(2.0),
            }),
            ScanPace::Sparing => Some(PaceSpacing {
                anywhere: Duration::from_millis(100),
                at_host: Duration::from_millis(100),
                patience: patience(1.5),
            }),
            ScanPace::Gentle => Some(PaceSpacing {
                anywhere: Duration::from_millis(5),
                at_host: Duration::from_millis(50),
                patience: None,
            }),
            ScanPace::Normal | ScanPace::Brisk | ScanPace::Hurried => None,
        }
    }
}

/// The patience [`ScanPace::Hurried`] scales every wait by, on top of what
/// [`ScanEffort::Fast`] already takes off.
///
/// Half, so the level is a clear step past `brisk`: `Fast` waits six tenths of the
/// usual time, and this makes it three tenths. No scale moves the floor every policy
/// keeps under its timeouts, so this shortens only the long waits a slow path earns.
const HURRIED_PATIENCE: f64 = 0.5;

/// What a slow [`ScanPace`] writes: the gap across the scan, the gap at one
/// host, and the patience where it raises it.
struct PaceSpacing {
    anywhere: Duration,
    at_host: Duration,
    patience: Option<TimeoutScale>,
}

impl fmt::Display for ScanPace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// The error parsing a [`ScanPace`] returns. Its message lists the accepted names, so a
/// front end can print it verbatim.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownScanPace {
    /// What the caller wrote.
    pub input: String,
}

impl fmt::Display for UnknownScanPace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown scan pace '{}', ", self.input)?;
        expected_levels(ScanPace::ALL, ScanPace::name, f)
    }
}

impl std::error::Error for UnknownScanPace {}

impl FromStr for ScanPace {
    type Err = UnknownScanPace;

    /// Parses a pace written as its name or its number, ignoring case and
    /// surrounding whitespace.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::ScanPace;
    ///
    /// assert_eq!("Gentle".parse(), Ok(ScanPace::Gentle));
    /// assert_eq!("0".parse(), Ok(ScanPace::Trickle));
    /// assert!("6".parse::<ScanPace>().is_err());
    /// ```
    fn from_str(input: &str) -> Result<Self, Self::Err> {
        parse_level(input, Self::ALL, Self::name, Self::from_level).ok_or_else(|| UnknownScanPace {
            input: input.to_string(),
        })
    }
}

/// A multiplier on how long a scan is willing to wait.
///
/// Always positive and finite. Zero, negative and NaN scales cannot be honoured, and
/// would otherwise be dropped where the policy is built while the report still recorded
/// them as applied.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct TimeoutScale(f64);

impl TimeoutScale {
    /// The scale `factor` names, or `None` if no schedule could be built from
    /// it: zero, negative, infinite, or NaN.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::config::TimeoutScale;
    ///
    /// assert!(TimeoutScale::new(2.5).is_some());
    /// assert!(TimeoutScale::new(0.0).is_none());
    /// assert!(TimeoutScale::new(f64::NAN).is_none());
    /// ```
    pub fn new(factor: f64) -> Option<Self> {
        (factor.is_finite() && factor > 0.0).then_some(Self(factor))
    }

    /// The multiplier, as the number a duration is scaled by.
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl fmt::Display for TimeoutScale {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// User control over retransmission, applied on top of each scanner's own
/// profile.
///
/// Comparable so a report can state whether two runs asked for the same effort. Not
/// [`Eq`], because `timeout_scale` is a float.
///
/// Every override is optional and typed narrowly enough that any value reaching this
/// struct is one the engine can honour; see [`TimeoutScale`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RetryConfig {
    /// How hard the scan tries before the fields below override any part of it.
    pub effort: ScanEffort,
    /// Replaces the attempt budget outright, whatever `effort` implies. One
    /// attempt disables retransmission.
    ///
    /// Non-zero: a zero would have to be silently raised to one where the policy is
    /// built.
    pub max_attempts: Option<NonZeroU8>,
    /// Multiplies how long the scan is willing to wait.
    ///
    /// The shortest timeout a policy allows is unaffected. That floor is what the
    /// protocol costs: retrying a UDP probe sooner than the target is permitted to
    /// answer only wastes a packet.
    pub timeout_scale: Option<TimeoutScale>,
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

/// The knobs a probing strategy is built from, carried together so adding one does not
/// change every constructor.
///
/// Not every strategy reads every field: local discovery builds its own Ethernet frames
/// and ignores [`SendMode`], while every strategy that sends a probe uses
/// [`RetryConfig`]. `max_probe_rate` is read by routed host discovery and the raw port
/// scanners: the sweep and the UDP scan are paced by it, while a TCP port scan paces
/// itself by a congestion window and treats it only as a ceiling. The unprivileged paths
/// pace themselves by their connection concurrency.
///
/// Built by [`ZondConfig::probe_tuning`] and, in tests, from [`Default`].
#[non_exhaustive]
#[derive(Debug, Clone, Default)]
pub struct ProbeTuning {
    /// Which layer a strategy puts its probes on the wire through, where it has
    /// the choice.
    pub send_mode: SendMode,

    /// How many attempts a probe gets and how long each waits, as an effort
    /// level with optional overrides.
    pub retry: RetryConfig,

    /// The most probes per second a strategy may emit, or `None` for the pacing
    /// each one arrives at on its own.
    ///
    /// Non-zero, since a ceiling of zero probes per second would be no scan at all.
    pub max_probe_rate: Option<NonZeroU32>,

    /// The fewest probes per second a strategy should emit, or `None` for
    /// whatever pace it arrives at.
    ///
    /// Read in the same places as [`max_probe_rate`](Self::max_probe_rate): a floor
    /// under a pace where the rate is the pace, and a floor under a ceiling where it is
    /// only a ceiling. Non-zero, since a floor of zero is what `None` already says.
    pub min_probe_rate: Option<NonZeroU32>,

    /// Which segment a TCP port probe carries. Read only by the raw TCP port scanner;
    /// host discovery always uses SYN, since the other techniques are no better at
    /// finding whether anything is there.
    pub tcp_technique: TcpScanTechnique,
    /// Which chunk an SCTP port probe carries. Read only by the raw SCTP port scanner;
    /// a sweep always sends an INIT, since a COOKIE-ECHO draws nothing from the open
    /// port a sweep hopes to hear from.
    pub sctp_technique: SctpScanTechnique,

    /// How far a strategy may go to identify the operating system behind a host.
    ///
    /// Read by the raw TCP port scanner, where the replies that carry a stack's shape
    /// arrive. At [`OsDetection::Passive`] it changes no packet and no timing.
    pub os_detection: OsDetection,

    /// How far a strategy may go to name what is behind an open port.
    ///
    /// Read by every strategy that fingerprints: the raw scanners, as a second pass over
    /// the ports they found, and the connect scanner, inline over the connection it
    /// already holds. Turning it off means neither completes a connection for
    /// identification.
    pub service_detection: ServiceDetection,

    /// What the caller has chosen to change about the probes each strategy emits.
    ///
    /// A default profile is inert. Read wherever a strategy chooses a probe field a
    /// caller may override; the conversations that follow a probe over their own
    /// connections ignore it. See [`EvasionProfile`], and
    /// [what a profile shapes](crate::evasion#a-profile-shapes-the-probes).
    pub evasion: EvasionProfile,

    /// Whether the capture admits ICMP errors for a technique that finds open
    /// and closed ports without them. See [`ZondConfig::icmp_evidence`].
    pub icmp_evidence: bool,

    /// Source addresses to force, one per family. See
    /// [`ZondConfig::send_source`].
    pub send_source: Vec<IpAddr>,
}

/// A third party whose IP-ID counter an idle scan reads to learn a target's ports
/// without addressing the target from the scanner's own address.
///
/// The idle (or zombie) scan is the quietest technique this engine has. Its probes carry
/// the zombie's source address, so the target answers the zombie. The result is read
/// from the zombie's global IP-ID counter, which advances by one for every packet the
/// zombie sends: read the counter, forge a probe, read it again. An open port drew an
/// answer the zombie had to reset, advancing the counter an extra step; a closed or
/// unreached one did not.
///
/// So the zombie must have a single shared IP-ID counter, and the forged probe needs a
/// self-built Ethernet frame to carry a source address the kernel would not choose. A
/// scan that cannot have both is refused; see the idle port scanner.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdleScan {
    /// The zombie's address.
    ///
    /// It must have a single global IP-ID counter (a counting generator, in the terms
    /// the OS-detection series uses), and be idle enough that its counter moves for
    /// this scan's probes and little else. The scan qualifies the zombie first and
    /// refuses an unsuitable one with the counter class it found.
    pub zombie: IpAddr,

    /// A port on the zombie to probe for its counter, or `None` for the engine's
    /// default.
    ///
    /// An unsolicited SYN/ACK draws a reset whether the port is open or closed, so any
    /// port works as long as the zombie's own filter does not drop the probe.
    pub zombie_port: Option<u16>,
}

impl IdleScan {
    /// An idle scan through `zombie`, on whichever port the engine picks.
    pub const fn new(zombie: IpAddr) -> Self {
        Self {
            zombie,
            zombie_port: None,
        }
    }

    /// Names the port on the zombie to read its counter from.
    ///
    /// For a zombie whose filter drops the engine's default. See
    /// [`zombie_port`](Self::zombie_port).
    #[must_use]
    pub const fn with_port(mut self, port: u16) -> Self {
        self.zombie_port = Some(port);
        self
    }
}

/// What a scan does, and what it is allowed to put on the wire.
///
/// Every field changes packets or timing. Rendering belongs to whoever embeds the crate:
/// the engine emits `tracing` events and installs no subscriber. This type is also the
/// record of how a scan was run, derived into every report as
/// [`ScanSettings`](crate::report::ScanSettings).
///
/// Start from [`default`](Default::default) and set the fields the scan needs:
///
/// ```
/// use zond_engine::ZondConfig;
///
/// let mut cfg = ZondConfig::default();
/// cfg.traceroute = true;
/// ```
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct ZondConfig {
    /// Forbids the scan from making any name query of its own: no A, AAAA or PTR query,
    /// to a resolver or to a host's multicast DNS responder. Found hosts are named only
    /// from the hosts file.
    ///
    /// Set it when the traffic itself is the problem: a query to a resolver the target
    /// operates announces the scan to whoever runs it. The cost is that hosts missing
    /// from the hosts file are reported by address, and active operating-system
    /// identification asks for a device-info record only from hosts whose `.local` name
    /// the scan already holds.
    ///
    /// Port probes are unaffected: a UDP probe of a name service's port still carries
    /// that service's question, and the device-info question to a probed host is still
    /// asked.
    ///
    /// This governs only what this engine sends. Traffic the host's own stack generates
    /// is outside what this crate can promise.
    ///
    /// Reading the hosts file sends nothing. Resolve the targets of such a scan with
    /// [`Resolver::hosts_file_only`](crate::Resolver::hosts_file_only), so a lab box
    /// listed there is still a target and no name leaves the machine; the scan names
    /// found hosts from the same file.
    pub no_dns: bool,

    /// Whether discovery may probe the whole segment, beyond the addresses it was
    /// given.
    ///
    /// A segment sweep sends the ICMPv6 all-nodes echo, which every IPv6 neighbour may
    /// answer, and records those that do. That is right for a sweep of `lan`, where an
    /// IPv6 neighbour with no address in the IPv4 range is found no other way. It is
    /// wrong for a scan of one named address, where a report listing eight machines
    /// would be surprising and, on someone else's network, indiscreet.
    ///
    /// Off by default. The engine receives already-resolved addresses and cannot tell
    /// `lan` from the range it expanded to, so whoever parsed the target expression has
    /// to set this.
    pub segment_sweep: bool,

    /// Whether a port scan skips the liveness check and scans every target.
    ///
    /// Off by default, so [`scan`](crate::scan) confirms a target is there before
    /// probing its ports. Without the check, a dead address costs a full scan and comes
    /// back with every port as no reply.
    ///
    /// Set it when the liveness check is wrong: a host behind a firewall that drops
    /// ICMP and answers nothing on the discovery ports is reported down and never
    /// scanned, though it may be up.
    ///
    /// The liveness phase probes only the addresses it was given; see
    /// [`segment_sweep`](Self::segment_sweep) for sweeping a segment.
    pub assume_up: bool,

    /// Whether to measure the route to each host that answered.
    ///
    /// Off by default. A trace costs roughly one probe per router per host and
    /// describes the network in between, not the host: useful for mapping a network,
    /// not for auditing a server.
    ///
    /// Only hosts that answered something are traced, because a path is measured
    /// backwards from the target's distance, read from a reply it sent. See
    /// [`traceroute`](crate::scanner::strategy::topology::traceroute).
    ///
    /// Needs raw sockets. An unprivileged run records the refusal, since an empty path
    /// would read as a network with no routers.
    pub traceroute: bool,

    /// Whether to characterise the filter in front of each host that answered.
    ///
    /// Off by default: it costs a handful of extra probes per live host and describes
    /// the filtering between scanner and host, which a firewall test wants and an
    /// inventory scan does not.
    ///
    /// A separate pass, run after the ports are known and only against hosts that
    /// answered. Its diagnostic probes are read as
    /// [`Filtering`](crate::model::host::Filtering) conclusions and leave the port
    /// verdicts alone; its bad-checksum probe would make every port read as no reply if
    /// a scan ran under it.
    pub characterise: bool,

    /// Which IP protocols to ask each host that answered whether it takes
    /// delivery of, one layer below the ports.
    ///
    /// Empty by default, which runs no pass: it costs a probe per host per protocol.
    /// It reveals a firewall's *protocol* policy, often the more telling one on a
    /// perimeter review, and what a host with no open TCP port still terminates: a
    /// tunnel endpoint answers for 47, 50 or 51 and a router for 89 or 112.
    ///
    /// [`DEFAULT_PROTOCOLS`](crate::scanner::strategy::protocols::DEFAULT_PROTOCOLS)
    /// is a sensible set for a caller who wants the pass without choosing numbers. The
    /// full `0..=255` range costs a raw socket per number, so it has to be asked for.
    ///
    /// A separate pass, run after the ports are known and only against hosts that
    /// answered. Its results are [`IpProtocolState`](crate::model::host::IpProtocolState)
    /// verdicts on the host; port verdicts are untouched.
    pub ip_protocols: BTreeSet<u8>,

    /// Whether to establish every version and cipher suite each TLS port *accepts*.
    ///
    /// Off by default because of the cost. Service detection records the one version
    /// and suite a single handshake negotiated. This offers the endpoint each version in
    /// turn and narrows the cipher list until it stops answering, so the report says
    /// what the endpoint *would* negotiate, which is what PCI scans, ASV reports and
    /// internal audits ask.
    ///
    /// The cost is connections: a dozen for a current server accepting a handful of
    /// suites, a few dozen for one accepting everything under three versions. Each is a
    /// bare TCP connection carrying one ClientHello, torn down before the handshake
    /// completes, so no application sees a session, but the target's connection log
    /// sees every one.
    ///
    /// A separate pass, run after service detection, which supplies the list of TLS
    /// ports. Bounded per host by [`host_timeout`](Self::host_timeout), worth setting
    /// alongside this on anything unattended.
    ///
    /// ```
    /// # use zond_engine::ZondConfig;
    /// # use std::time::Duration;
    /// let mut cfg = ZondConfig::default();
    /// cfg.tls_enumeration = true;
    /// cfg.host_timeout = Some(Duration::from_secs(120));
    /// ```
    pub tls_enumeration: bool,

    /// The TCP ports a scan connects to and listens on, and sends nothing.
    ///
    /// [`RAW_PRINT_PORTS`] by default. A printer prints whatever bytes arrive on those,
    /// so each probe would be a page of gibberish. The rule follows the port number,
    /// because identifying the host as a printer would take the very probe that prints.
    ///
    /// On a listed port, identification reads only what the port volunteers on
    /// connecting, as [`ServiceDetection::Banner`] does, and no detection, TLS
    /// handshake, enumeration or other conversation is opened. Finding the port open is
    /// unaffected, since that probe carries no payload. The report records this set,
    /// so a reader can tell a port left unprobed on purpose from one with nothing to
    /// say; see
    /// [`ScanSettings::listen_only_ports`](crate::report::ScanSettings::listen_only_ports).
    /// To send a port nothing at all, exclude it; see
    /// [`excluded_ports`](Self::excluded_ports).
    ///
    /// Clear it to probe these ports like any other, accepting that a printer may
    /// print. Add ports whose devices cannot be trusted with an unexpected request.
    /// UDP is unaffected.
    ///
    /// ```
    /// # use zond_engine::ZondConfig;
    /// let mut cfg = ZondConfig::default();
    /// assert!(cfg.listen_only_ports.contains(&9100));
    /// // Probe the printers' ports too, knowing each probe may print.
    /// cfg.listen_only_ports.clear();
    /// ```
    pub listen_only_ports: BTreeSet<u16>,

    /// When set, scan TCP ports through a third-party zombie. See [`IdleScan`].
    ///
    /// This replaces the ordinary TCP port scan, so
    /// [`tcp_technique`](Self::tcp_technique) does not apply: every probe is a forged
    /// SYN read through the zombie's counter. UDP targets are left unprobed, since a
    /// UDP port cannot be read this way and probing it directly would reveal the
    /// scanner. Without privilege, a self-built frame, or a suitable zombie, the scan is
    /// refused; it never falls back to the scanner's own address.
    pub idle_scan: Option<IdleScan>,

    /// Addresses this scan may not probe, whatever else it was asked to cover.
    ///
    /// Empty by default. This is how an engagement scoped as "10.0.0.0/8, except the
    /// cardholder segment" is expressed, and breaking it breaks a contract.
    ///
    /// Enforced twice, before the first packet and again at every finding; see
    /// [`Exclusions`] for why. The second check matters because a segment sweep learns
    /// addresses that were never in the target list.
    ///
    /// Narrowing only: no value can make a scan send a packet it would not otherwise
    /// send, which makes it safe to accept from a settings file (unlike
    /// [`segment_sweep`](Self::segment_sweep)). See `import::settings::Settings`.
    pub exclusions: Exclusions,

    /// Ports this scan may not probe on any target, whatever else it was asked
    /// to cover.
    ///
    /// Empty by default. Removed from the port list before anything numbers it, so the
    /// port scan never asks an excluded port, and the passes that follow
    /// (identification, detection, TLS enumeration, the operating-system series,
    /// filter characterisation, route tracing) work from the ports it found. Ports a
    /// pass picks for itself are held to it too: a liveness pass skips excluded common
    /// ports, and the operating-system passes send no SNMP or device-info question to a
    /// port excluded on UDP. The report records the set; see
    /// [`ScanSettings::excluded_ports`](crate::report::ScanSettings::excluded_ports).
    ///
    /// For a port whose device misbehaves when anything arrives, or that an engagement
    /// puts out of bounds. Stronger than [`listen_only_ports`](Self::listen_only_ports),
    /// which still finds a port open: this sends the port nothing. The raw-print ports
    /// default to the weaker setting, since a printer prints what a connection carries,
    /// not the handshake, and excluding them would hide the printers.
    ///
    /// Not covered: name lookups, which [`no_dns`](Self::no_dns) decides, and the
    /// [IP protocol pass](Self::ip_protocols), which asks about a protocol and aims at
    /// a port chosen to be closed.
    ///
    /// Narrowing only, like [`exclusions`](Self::exclusions), so it is safe to accept
    /// from a settings file.
    ///
    /// ```
    /// # use zond_engine::ZondConfig;
    /// # use zond_engine::model::port::PortSet;
    /// let mut cfg = ZondConfig::default();
    /// // The raw-print ports, sent nothing at all.
    /// cfg.excluded_ports = PortSet::try_from("9100-9107").unwrap();
    /// ```
    pub excluded_ports: crate::model::port::PortSet,

    /// The name each address was asked for by, where a target named a host.
    ///
    /// A web server routes a request by the name in it (the `Host` header, or the TLS
    /// server name), and a server holding several sites at one address answers an
    /// unnamed request with its default site or refuses the handshake. So a port on an
    /// address reached by name is identified using that name, and the host's record
    /// carries it as its hostname, which a reverse lookup leaves alone.
    ///
    /// Only names that were written are used, never one a lookup, report or redirect
    /// suggests. Where two names led to one address, the first written wins.
    ///
    /// One name per address, because a port holds one identification and one TLS
    /// record. The certificate the first name drew is not checked against a second
    /// name, since a server choosing its certificate by name would present a different
    /// one. To identify each site and check its certificate, scan each name in its own
    /// run.
    ///
    /// Empty by default, and set by whoever resolved the target expressions, since the
    /// names are gone once a scan has addresses; see
    /// [`resolve::for_port_scan`](crate::resolve::for_port_scan).
    pub target_names: BTreeMap<IpAddr, String>,

    /// Whether identifying detail should be masked wherever the scan's findings
    /// leave the process: hostnames, hardware addresses, and the host part of an
    /// IPv6 address.
    ///
    /// For a report going somewhere that needs a network's shape without knowing
    /// which device is which: a client, an auditor, a screenshot in an issue.
    ///
    /// The scan itself keeps everything it found. This records the caller's intent,
    /// which reaches the point of use through [`ScanSettings`](crate::report::ScanSettings)
    /// and the export layer's [`Redaction`](crate::export::Redaction) policy, so the
    /// unmasked data stays recoverable.
    pub redact: bool,

    /// How raw SYN probes are placed on the wire. Defaults to
    /// [`SendMode::Auto`], which is correct on every supported platform;
    /// override it only to force Layer-2 sends for host-stack-bypass scanning.
    pub send_mode: SendMode,

    /// The fastest a scan may put probes on the wire, in probes per second.
    /// `None` leaves each scanner's own default in force.
    ///
    /// Mainly a coverage control. A probe's chance of being answered falls as the rate
    /// rises: on a policed path a burst loses most of its first attempt, recovered if
    /// at all by retransmitting later. A lower rate buys first-attempt coverage; a
    /// higher one trades coverage for time.
    ///
    /// For a TCP port scan it is only a ceiling. That scan learns how fast each target
    /// answers and settles there, almost always well below any configured rate (see
    /// `congestion`), so this matters only for a target that must not be pushed. The
    /// discovery sweep and the UDP port scan *are* paced by it, having no evidence to
    /// adapt on.
    ///
    /// Non-zero, since a ceiling of zero would be no scan and the report must not
    /// record a ceiling that was never applied.
    pub max_probe_rate: Option<NonZeroU32>,

    /// The slowest a scan may put probes on the wire, in probes per second.
    /// `None` leaves each scanner's own pace in force.
    ///
    /// For a plan so large that finishing is in doubt. A scan with a
    /// [`scan_timeout`](Self::scan_timeout) can spend its whole budget on a fraction of
    /// its targets and report the rest as
    /// [`timed_out`](crate::report::ScanPhase::timed_out); a floor keeps the pace high
    /// enough to finish in time.
    ///
    /// Read by the same strategies as [`max_probe_rate`](Self::max_probe_rate). The
    /// discovery sweep and the UDP port scan are paced by the rate, so a floor raises
    /// their pace. A TCP port scan reads the rate only as a ceiling, so a floor raises
    /// the ceiling and its congestion window still decides, since pushing a target
    /// harder than it answers loses coverage.
    ///
    /// A floor above an explicit [`max_probe_rate`](Self::max_probe_rate) does not
    /// lift it: the safety limit wins.
    ///
    /// Non-zero, since a floor of zero is what `None` already says.
    pub min_probe_rate: Option<NonZeroU32>,

    /// The shortest gap between two probes aimed at one host, or `None` to let
    /// every pass send as fast as its own pacing allows.
    ///
    /// **Every length is read literally, `Duration::MAX` included.** "No limit" is
    /// `None`; the largest gap admits one probe per host and never another, so a scan
    /// asking a host more than one question waits until stopped by the caller or by
    /// [`scan_timeout`](Self::scan_timeout), and files what it never asked as
    /// [`Unasked`](crate::model::port::PortState::Unasked). Reading the maximum as "no
    /// gap" would turn spacing off for a gap computed by saturating arithmetic, exactly
    /// when the caller asked for the most of it.
    ///
    /// This expresses what an operator knows about a target: this appliance falls over
    /// above twenty probes a second, this sensor fires at more than one every hundred
    /// milliseconds. Those limits are per source and destination, which
    /// [`max_probe_rate`](Self::max_probe_rate) cannot express without throttling the
    /// whole range.
    ///
    /// A duration because that is what the gate holds; converting a rate would round,
    /// and the report would record a bound the scan never applied (see `pacing_for`).
    ///
    /// The plan's keyed order already interleaves hosts in a scan of many, but that
    /// gives no bound, and nothing at all for a scan of one fragile address.
    ///
    /// A held probe is deferred, not dropped, so a tight gap makes a scan take longer.
    /// With [`scan_timeout`](Self::scan_timeout) set, the report says which hosts the
    /// budget left part-scanned.
    ///
    /// ## What reads this
    ///
    /// Every pass that sends toward a target, privileged or not: the raw port scans,
    /// the routed and segment sweeps, the identification, characterisation,
    /// IP-protocol, route and idle passes, and every connection and datagram opened
    /// through the host's own TCP and UDP (the connect scans and sweep, service
    /// identification and its further connections, TLS enumeration, the detections,
    /// and the SNMP and multicast DNS questions). All take slots from one shared gate,
    /// deciding and recording in one step, so concurrent passes share one gap.
    ///
    /// Three things send without it. The passive listener sends nothing. Next-hop
    /// hardware address resolution and name queries go to a neighbour or a name
    /// server, not a target. The timestamp series is timed: its spacing is the
    /// measurement. It runs under this gap unchanged; see
    /// [`probe_interval`](Self::probe_interval) for the gap it does not.
    ///
    /// ## What a gap counts
    ///
    /// One probe. On the raw paths that is one packet except in two places, where a
    /// question sent as several back-to-back packets counts as one probe, since
    /// deferring part of it would leave the rest unanswerable. The identification pass
    /// asks an IPv4 target for an echo and a timestamp (two packets). The routed sweep
    /// asks on each of its [`SynPorts`](crate::scanner::strategy::routed::SynPorts)
    /// (five, or up to eight in a port scan's liveness pass). So a gap of 100 ms admits
    /// that many packets per tenth of a second at one address while those run, and one
    /// elsewhere.
    ///
    /// Over the host's own sockets, one probe is one connection attempt (retries and
    /// redials included) or the first datagram of one exchange. The conversation over
    /// an answered connection is not spaced. A probe waits for its slot before its
    /// socket is opened, and the wait counts against no connection or conversation
    /// timeout, so a long gap costs time but never an identification.
    ///
    /// The idle scan counts a read of its zombie's counter at the zombie and each
    /// forged probe at the target. A route trace counts each probe at its target,
    /// though routers on the way answer it.
    ///
    /// A probe this machine refused before anything left (no descriptor, no source
    /// address, a local route's refusal) gets its slot back. A probe still waiting when
    /// the scan stops or its host's budget runs out is never sent and is reported as
    /// never asked.
    pub host_probe_interval: Option<Duration>,

    /// The shortest gap between any two probes the scan sends, whatever host
    /// each is aimed at, or `None` to leave the pace to each pass.
    ///
    /// The scan-wide counterpart of [`host_probe_interval`](Self::host_probe_interval),
    /// for when the path must not be pushed: a thin link, a busy firewall's session
    /// table, an owner who asked for a few packets a second. A gap of a second is one
    /// probe a second across the whole range, where the same per-host gap still lets a
    /// scan of a thousand hosts send a thousand a second.
    ///
    /// A duration because the pacing gate holds one, and because this is used at the
    /// slow end, where [`max_probe_rate`](Self::max_probe_rate), a whole number per
    /// second, cannot express one probe every five seconds.
    ///
    /// [`max_probe_rate`](Self::max_probe_rate) is each pass's own ceiling, so two
    /// concurrent passes may each reach it. This gap is shared and claimed probe by
    /// probe, so concurrent passes divide it.
    ///
    /// It applies to the same probes as [`host_probe_interval`](Self::host_probe_interval),
    /// counted the same way and read literally on the same terms, `Duration::MAX`
    /// included. A probe waits out whichever gap ends later. It also covers the frames
    /// the segment sweep sends to a group (the router solicitation, the configuration
    /// request and the all-nodes echo), which spend this gap and no host's.
    ///
    /// The timestamp series is skipped under a gap longer than its send cadence of a
    /// quarter of a millisecond: its samples are read for the interval between them,
    /// and spread out they would read as a stalled counter. The report's record of
    /// this gap accounts for that, and hosts are named by the remaining
    /// operating-system passes.
    ///
    /// A held probe is deferred, not dropped: a thousand ports a second apart is a
    /// quarter of an hour before any retry. With [`scan_timeout`](Self::scan_timeout)
    /// set, the report says which hosts the budget left part-scanned.
    pub probe_interval: Option<Duration>,

    /// The longest a scan will keep working on one host before leaving it with
    /// what it has, or `None` for no bound.
    ///
    /// The clock starts on the first probe aimed at an address and covers every later
    /// pass that sends to it: the port scan, the service pass, and the identification,
    /// path and detection passes. Once it expires the host is left alone and its
    /// address is written into
    /// [`ScanPhase::timed_out`](crate::report::ScanPhase::timed_out), so a short port
    /// list is not mistaken for a quiet machine.
    ///
    /// For a host that answers slowly: silence already costs a known number of
    /// probes, but a tarpit, a rate-limited appliance or a stack answering one probe in
    /// ten costs whatever it decides to.
    ///
    /// Not covered: reverse lookups, which go to a resolver (see
    /// [`no_dns`](Self::no_dns)), and discovery, whose liveness sweep runs a fixed
    /// schedule per address (see [`scan_timeout`](Self::scan_timeout)).
    ///
    /// It stops new probes, not those in flight, so a host may keep answering until
    /// the retry schedule of its last window runs out. That tail is bounded by the
    /// schedule.
    ///
    /// Zero expires before the first probe: the scan asks nothing and records every
    /// host as cut short.
    pub host_timeout: Option<Duration>,

    /// The longest the whole call may run before it winds down, or `None` for
    /// no bound.
    ///
    /// Measured from when the scan is assembled, covering every phase: discovery, the
    /// port scan, and everything that enriches their findings. On expiry the strategies
    /// stop on their next pass and the run ends as an aborted one does, except each
    /// scanner records [`StopReason::TimedOut`](crate::report::StopReason::TimedOut).
    ///
    /// This makes an unattended run safe to schedule. The other bounds cover a probe, a
    /// retry or a host, and a range with enough slow addresses has no finishing time a
    /// caller can work out in advance.
    ///
    /// What was found is kept, and ports with no verdict are recorded
    /// [`Unasked`](crate::model::port::PortState::Unasked).
    ///
    /// It bounds this call, so each sitting of a resumed scan gets the full budget
    /// again; bounding the whole job is up to the caller.
    ///
    /// A budget longer than a clock can count from now, such as `Duration::MAX`, never
    /// runs out.
    pub scan_timeout: Option<Duration>,

    /// Which segment a TCP port probe carries, and so what its answers mean.
    ///
    /// Defaults to [`TcpScanTechnique::Syn`], the only technique that identifies an open
    /// port positively and the only one the unprivileged connect fallback can
    /// approximate. The rest need raw sockets; asking for one without them records a
    /// failure, since a connect scan answers a different question.
    ///
    /// Affects the port-scan phase only. [`discover`](crate::scanner::discover)
    /// is unaffected.
    pub tcp_technique: TcpScanTechnique,

    /// Which chunk an SCTP port probe carries, and so what its answers mean.
    ///
    /// Defaults to [`SctpScanTechnique::Init`], the only technique that names an open
    /// SCTP port. [`CookieEcho`](SctpScanTechnique::CookieEcho) draws an answer only
    /// from a port with nothing behind it, so its best verdict is open or no reply, but
    /// it passes filters written against INIT.
    ///
    /// Both need raw sockets. Affects the port-scan phase only: a discovery sweep always
    /// sends an INIT.
    pub sctp_technique: SctpScanTechnique,

    /// How hard the scan tries before accepting silence as an answer.
    ///
    /// Scales each probing path's own schedule, so no effort level can hand a scanner a
    /// schedule its protocol cannot satisfy. Defaults to [`ScanEffort::Balanced`].
    pub retry: RetryConfig,

    /// How far the scan goes to identify the operating system behind each host.
    ///
    /// Defaults to [`OsDetection::Passive`], which reads replies the scan already drew
    /// and sends nothing. See [`OsDetection`] for what each level puts on the wire.
    pub os_detection: OsDetection,

    /// How far the scan goes to identify what is listening behind each open
    /// port.
    ///
    /// Defaults to [`ServiceDetection::Probe`], which connects to every open port and
    /// asks what it is. A scan that must stay out of the target's application logs
    /// turns it off. Affects the port-scan phase only.
    pub service_detection: ServiceDetection,

    /// How intrusive a detection the scan may run against an identified service.
    ///
    /// After service detection names a port, the flow corpus can probe further to find
    /// what is *wrong* with it. This is the ceiling on how far that goes. The default
    /// permits only passive detections, which read what the service pass collected;
    /// active-benign ones, and ones that mutate, exploit or degrade the target, run
    /// only when the operator raises the ceiling. See [`DetectionEnvelope`]'s `Default`.
    /// Read by the detection phase, and only when service detection ran.
    pub detection: DetectionEnvelope,

    /// What the scan changes about the probes it sends, over the defaults.
    ///
    /// Defaults to an inert profile. Carried into [`probe_tuning`](Self::probe_tuning)
    /// for the strategies, and into the report. The conversations that follow a probe
    /// over their own connections are not shaped; see
    /// [what a profile shapes](crate::evasion#a-profile-shapes-the-probes).
    pub evasion: EvasionProfile,

    /// Whether to capture ICMP errors for a technique that finds open and
    /// closed ports without them, such as a SYN scan. On by default.
    ///
    /// An ICMP error is a firewall answering, and it tells a
    /// [`Blocked`](crate::model::port::PortState::Blocked) port from one that drew
    /// [`NoReply`](crate::model::port::PortState::NoReply). A scan too outrun to read
    /// silence as a verdict can still report a refusal. Turn it off on a link noisy
    /// with ICMP. The other TCP techniques read ICMP for their verdicts regardless.
    pub icmp_evidence: bool,

    /// Source addresses to send probes to routed targets from, overriding the routing
    /// table's choice. At most one per family is used; empty lets the host decide. Set
    /// it to send from a chosen interface when the default route is a VPN the
    /// link-layer path cannot traverse.
    ///
    /// Connections follow the probes: the connect scan, the service pass, TLS
    /// enumeration and the detections all reach a routed target from the forced source
    /// through its interface. Targets on a directly attached link, and targets of a
    /// family with no forced source, follow the routing table, so with only an IPv4
    /// source forced, an IPv6 target may still go through a VPN holding the default
    /// route. To avoid the routing table entirely, force a source for each family the
    /// targets span.
    ///
    /// A connection is held to its interface by binding the socket to it, which Linux
    /// allows without `CAP_NET_RAW` from 5.7 on. On older kernels an unprivileged
    /// scan's pinned connections are refused, and their targets are reported as
    /// unreachable from this host.
    ///
    /// Name lookups are not pinned. Reverse lookups ask the configured resolvers and
    /// each interface's gateway by the routing table, as the system resolver does.
    /// Under a full-tunnel VPN the configured resolver is often reachable only through
    /// the tunnel, so a pinned lookup would fail, and the system resolver opens its own
    /// sockets anyway. To keep the scan's names off the tunnel, set
    /// [`no_dns`](Self::no_dns).
    pub send_source: Vec<IpAddr>,
}

impl Default for ZondConfig {
    /// Hand-written so [`icmp_evidence`](Self::icmp_evidence) defaults on and
    /// [`listen_only_ports`](Self::listen_only_ports) to the printers' ports;
    /// every other field takes its own type's default.
    fn default() -> Self {
        Self {
            icmp_evidence: true,
            send_source: Vec::new(),
            no_dns: Default::default(),
            segment_sweep: Default::default(),
            assume_up: Default::default(),
            traceroute: Default::default(),
            characterise: Default::default(),
            ip_protocols: Default::default(),
            tls_enumeration: Default::default(),
            listen_only_ports: RAW_PRINT_PORTS.iter().copied().collect(),
            idle_scan: Default::default(),
            exclusions: Default::default(),
            excluded_ports: Default::default(),
            target_names: Default::default(),
            redact: Default::default(),
            send_mode: Default::default(),
            max_probe_rate: Default::default(),
            min_probe_rate: Default::default(),
            host_probe_interval: Default::default(),
            probe_interval: Default::default(),
            host_timeout: Default::default(),
            scan_timeout: Default::default(),
            tcp_technique: Default::default(),
            sctp_technique: Default::default(),
            retry: Default::default(),
            os_detection: Default::default(),
            service_detection: Default::default(),
            detection: Default::default(),
            evasion: Default::default(),
        }
    }
}

impl ZondConfig {
    /// The probe-level knobs, bundled for the strategies that need them.
    ///
    /// `self` is destructured with every field named, so a new field not handled here
    /// fails to compile. The dropped fields govern which phases run and where a scan
    /// may go, which the orchestrator decides.
    pub fn probe_tuning(&self) -> ProbeTuning {
        let Self {
            send_mode,
            retry,
            max_probe_rate,
            min_probe_rate,
            tcp_technique,
            sctp_technique,
            os_detection,
            service_detection,
            evasion,
            icmp_evidence,
            send_source,

            // Read elsewhere.
            no_dns: _,
            segment_sweep: _,
            assume_up: _,
            traceroute: _,
            characterise: _,
            ip_protocols: _,
            tls_enumeration: _,
            idle_scan: _,
            // Held by the scan's context, which every pass asks before sending to
            // a port.
            listen_only_ports: _,
            exclusions: _,
            // Taken out of the port list before a scan starts, and read by the
            // passes that pick a port of their own.
            excluded_ports: _,
            // Read by the identification, which asks each port by it.
            target_names: _,
            redact: _,
            detection: _,

            // The wall-clock bounds: the scan's rides on the `ScanHandle` every
            // probing loop reads, the host's on the context the strategies share.
            host_timeout: _,
            scan_timeout: _,

            // The gaps live in one gate every pass claims from; a copy per
            // strategy would let each pass use the whole gap.
            host_probe_interval: _,
            probe_interval: _,
        } = self;

        ProbeTuning {
            send_mode: *send_mode,
            retry: *retry,
            max_probe_rate: *max_probe_rate,
            min_probe_rate: *min_probe_rate,
            tcp_technique: *tcp_technique,
            sctp_technique: *sctp_technique,
            os_detection: *os_detection,
            service_detection: *service_detection,
            evasion: evasion.clone(),
            icmp_evidence: *icmp_evidence,
            send_source: send_source.clone(),
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

    /// A scan left as it came sends nothing to a printer's raw-print ports,
    /// 9100 and the seven queues after it, and nothing else is spared.
    ///
    /// The default is the protection: a front end unaware of the setting still prints
    /// nothing.
    #[test]
    fn a_default_scan_only_listens_on_the_raw_print_ports() {
        let cfg = ZondConfig::default();
        assert_eq!(
            cfg.listen_only_ports,
            (9100..=9107).collect::<BTreeSet<u16>>()
        );
        assert_eq!(
            crate::report::ScanSettings::from(&cfg).listen_only_ports,
            (9100..=9107).collect::<Vec<u16>>(),
            "the report records what the scan held back"
        );
    }

    /// The capture knob reaches the strategies.
    #[test]
    fn icmp_evidence_reaches_the_probe_tuning_and_is_on_unless_declined() {
        let mut cfg = ZondConfig::default();
        assert!(
            cfg.probe_tuning().icmp_evidence,
            "an error is a verdict a scan that was outrun cannot reach any other way"
        );

        cfg.icmp_evidence = false;
        assert!(
            !cfg.probe_tuning().icmp_evidence,
            "and a caller may decline it"
        );
    }
    use super::*;
    use std::num::NonZeroU8;

    /// What holds for one scale holds for all of them.
    #[test]
    fn every_scale_agrees_with_its_own_numbering() {
        fn check<T: Copy + std::fmt::Debug + PartialEq>(
            all: &[T],
            name: fn(T) -> &'static str,
            level: fn(T) -> u8,
            from_level: fn(u8) -> Option<T>,
        ) {
            for (index, value) in all.iter().copied().enumerate() {
                assert_eq!(usize::from(level(value)), index, "{value:?}");
                assert_eq!(from_level(level(value)), Some(value), "{value:?}");
                assert!(!name(value).is_empty());
            }
            let past_the_end = all.len() as u8;
            assert_eq!(
                from_level(past_the_end),
                None,
                "a level this engine does not offer is refused, not rounded down"
            );
        }

        check(
            ScanEffort::ALL,
            ScanEffort::name,
            ScanEffort::level,
            ScanEffort::from_level,
        );
        check(
            OsDetection::ALL,
            OsDetection::name,
            OsDetection::level,
            OsDetection::from_level,
        );
        check(
            ServiceDetection::ALL,
            ServiceDetection::name,
            ServiceDetection::level,
            ServiceDetection::from_level,
        );
        check(
            ScanPace::ALL,
            ScanPace::name,
            ScanPace::level,
            ScanPace::from_level,
        );
    }

    /// Both spellings are one setting for every scale: `2` from a flag and `balanced`
    /// from a settings file must give the same scan.
    #[test]
    fn every_scale_parses_the_same_by_name_and_by_number() {
        for &effort in ScanEffort::ALL {
            assert_eq!(effort.name().parse(), Ok(effort));
            assert_eq!(effort.name().to_uppercase().parse(), Ok(effort));
            assert_eq!(format!("  {}  ", effort.level()).parse(), Ok(effort));
        }
        assert!("4".parse::<ScanEffort>().is_err());
        assert!("maximum".parse::<ScanEffort>().is_err());

        for &detection in OsDetection::ALL {
            assert_eq!(detection.name().parse(), Ok(detection));
            assert_eq!(detection.level().to_string().parse(), Ok(detection));
        }
        for &detection in ServiceDetection::ALL {
            assert_eq!(detection.name().parse(), Ok(detection));
            assert_eq!(detection.level().to_string().parse(), Ok(detection));
        }
        for &pace in ScanPace::ALL {
            assert_eq!(pace.name().parse(), Ok(pace));
            assert_eq!(pace.level().to_string().parse(), Ok(pace));
        }
    }

    /// The message a front end prints is built from the levels themselves, so a new
    /// level is named in it.
    #[test]
    fn a_parse_error_names_every_level_that_would_have_worked() {
        let effort = "maximum".parse::<ScanEffort>().unwrap_err().to_string();
        for &level in ScanEffort::ALL {
            assert!(effort.contains(level.name()), "{effort} omits {level}");
        }
        assert!(effort.contains("0 to 3"), "{effort}");

        let os = "9".parse::<OsDetection>().unwrap_err().to_string();
        for &level in OsDetection::ALL {
            assert!(os.contains(level.name()), "{os} omits {level}");
        }

        let service = "exhaustive"
            .parse::<ServiceDetection>()
            .unwrap_err()
            .to_string();
        for &level in ServiceDetection::ALL {
            assert!(service.contains(level.name()), "{service} omits {level}");
        }
        assert!(service.contains("0 to 3"), "{service}");

        let pace = "6".parse::<ScanPace>().unwrap_err().to_string();
        for &level in ScanPace::ALL {
            assert!(pace.contains(level.name()), "{pace} omits {level}");
        }
        assert!(pace.contains("0 to 5"), "{pace}");
    }

    /// The default pace is the default scan, to the last field.
    ///
    /// A scan run at `normal` must be the scan run with no pace chosen. Compared as a
    /// whole, so a field added later is covered too.
    #[test]
    fn the_default_pace_changes_nothing() {
        let mut paced = ZondConfig::default();
        ScanPace::default().apply_to(&mut paced);
        assert_eq!(ScanPace::default(), ScanPace::Normal);
        assert_eq!(format!("{paced:?}"), format!("{:?}", ZondConfig::default()));
    }

    /// Every level is at least as gentle as the one above it: no slower level
    /// spaces probes closer, at one host or across the scan, or waits less
    /// for an answer.
    ///
    /// Patience is compared through a retry schedule, since effort and scale both move
    /// how long a probe is given.
    #[test]
    fn a_slower_pace_never_spaces_closer_or_waits_less() {
        use crate::scanner::pacing::retry::RetryPolicy;

        let policy = RetryPolicy::new(
            3,
            Duration::from_millis(500),
            Duration::from_millis(50),
            Duration::from_secs(3),
            2.0,
            0.2,
            None,
        );
        let paced: Vec<(Duration, Duration, Duration)> = ScanPace::ALL
            .iter()
            .map(|pace| {
                let mut cfg = ZondConfig::default();
                pace.apply_to(&mut cfg);
                (
                    cfg.probe_interval.unwrap_or_default(),
                    cfg.host_probe_interval.unwrap_or_default(),
                    policy.configured(cfg.retry).longest_probe_lifetime(),
                )
            })
            .collect();

        for (slower, faster) in ScanPace::ALL.iter().zip(&ScanPace::ALL[1..]) {
            let (a, b) = (
                paced[slower.level() as usize],
                paced[faster.level() as usize],
            );
            assert!(a.0 >= b.0, "{slower} spaces the scan closer than {faster}");
            assert!(a.1 >= b.1, "{slower} spaces a host closer than {faster}");
            assert!(a.2 >= b.2, "{slower} waits less than {faster}");
        }
        assert!(
            paced[0].0 > paced[5].0 && paced[0].2 > paced[5].2,
            "and the dial moves something from one end to the other"
        );
    }

    /// A slow pace takes the longer of its own gap and one already set, and the larger
    /// patience, so it never shortens a gap somebody chose.
    #[test]
    fn a_slow_pace_never_loosens_what_the_configuration_holds() {
        let mut cfg = ZondConfig {
            probe_interval: Some(Duration::from_secs(2)),
            host_probe_interval: Some(Duration::from_secs(3)),
            ..ZondConfig::default()
        };
        cfg.retry.timeout_scale = TimeoutScale::new(4.0);

        ScanPace::Gentle.apply_to(&mut cfg);
        ScanPace::Trickle.apply_to(&mut cfg);

        assert_eq!(cfg.probe_interval, Some(Duration::from_secs(2)));
        assert_eq!(cfg.host_probe_interval, Some(Duration::from_secs(3)));
        assert_eq!(cfg.retry.timeout_scale, TimeoutScale::new(4.0));

        // Where nothing was set, the level's own values are written.
        let mut fresh = ZondConfig::default();
        ScanPace::Gentle.apply_to(&mut fresh);
        assert_eq!(fresh.probe_interval, Some(Duration::from_millis(5)));
        assert_eq!(fresh.host_probe_interval, Some(Duration::from_millis(50)));
    }

    /// A fast pace changes only patience, never a gap or a rate, so it cannot lift a
    /// ceiling a settings file set to protect a network.
    #[test]
    fn a_fast_pace_touches_no_gap_and_no_rate() {
        for pace in [ScanPace::Brisk, ScanPace::Hurried] {
            let mut cfg = ZondConfig {
                max_probe_rate: NonZeroU32::new(100),
                probe_interval: Some(Duration::from_millis(250)),
                ..ZondConfig::default()
            };
            pace.apply_to(&mut cfg);

            assert_eq!(cfg.max_probe_rate, NonZeroU32::new(100), "{pace}");
            assert_eq!(cfg.min_probe_rate, None, "{pace}");
            assert_eq!(
                cfg.probe_interval,
                Some(Duration::from_millis(250)),
                "{pace}"
            );
            assert_eq!(cfg.retry.effort, ScanEffort::Fast, "{pace}");
        }
    }

    /// A scale no schedule can be built from is refused where it is set, so the report
    /// never records one that did not apply.
    #[test]
    fn a_retry_override_can_only_hold_a_value_a_scan_could_honour() {
        for factor in [0.0, -1.0, -0.0, f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            assert_eq!(TimeoutScale::new(factor), None, "scale {factor}");
        }
        assert_eq!(TimeoutScale::new(2.5).map(TimeoutScale::get), Some(2.5));

        // Absurd but honourable: the schedule it produces is the one asked for.
        assert!(TimeoutScale::new(f64::MIN_POSITIVE).is_some());
    }

    /// Every override in a retry configuration is a narrower type than the field
    /// it sets, so what reaches a strategy is what a scan can honour.
    #[test]
    fn the_retry_overrides_are_unset_by_default() {
        let retry = RetryConfig::default();
        assert_eq!(retry.max_attempts, None);
        assert_eq!(retry.timeout_scale, None);
        assert_eq!(retry.effort, ScanEffort::Balanced);
        assert!(retry.dampen_silent_hosts);
    }

    /// The knobs a strategy reads arrive intact. `probe_tuning` destructures `self`, so
    /// an omitted field fails to compile; this catches a field wired to the wrong place.
    #[test]
    fn every_probe_level_knob_reaches_the_strategies() {
        let cfg = ZondConfig {
            send_mode: SendMode::Ethernet,
            retry: RetryConfig {
                effort: ScanEffort::Thorough,
                max_attempts: NonZeroU8::new(7),
                timeout_scale: TimeoutScale::new(3.5),
                dampen_silent_hosts: false,
            },
            // Different numbers, so a bound copied from the other rate is caught.
            max_probe_rate: NonZeroU32::new(1234),
            min_probe_rate: NonZeroU32::new(567),
            tcp_technique: TcpScanTechnique::Xmas,
            sctp_technique: SctpScanTechnique::CookieEcho,
            os_detection: OsDetection::Aggressive,
            service_detection: ServiceDetection::Banner,
            evasion: EvasionProfile::default(),
            ..Default::default()
        };

        let tuning = cfg.probe_tuning();
        assert_eq!(tuning.send_mode, cfg.send_mode);
        assert_eq!(tuning.retry, cfg.retry);
        assert_eq!(tuning.max_probe_rate, cfg.max_probe_rate);
        assert_eq!(tuning.min_probe_rate, cfg.min_probe_rate);
        assert_eq!(tuning.tcp_technique, cfg.tcp_technique);
        assert_eq!(tuning.sctp_technique, cfg.sctp_technique);
        assert_eq!(tuning.os_detection, cfg.os_detection);
        assert_eq!(tuning.service_detection, cfg.service_detection);
        assert_eq!(tuning.evasion, cfg.evasion);
    }

    /// `connects` is what the target's application logs record; `sends` is what its
    /// services are handed. The two boundaries differ.
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

    /// Where the wire cost begins. The default level emits nothing, which is what makes
    /// it safe to leave on, so which levels answer `true` is a behavioural contract.
    #[test]
    fn os_detection_sends_nothing_below_the_active_level() {
        assert!(!OsDetection::Off.is_active());
        assert!(!OsDetection::Passive.is_active());
        assert!(OsDetection::Active.is_active());
        assert!(OsDetection::Aggressive.is_active());

        assert!(!OsDetection::default().is_active(), "the default is silent");
        assert!(OsDetection::default().is_enabled(), "and it is still on");
    }
}
