// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Settings and named profiles
//!
//! Defaults a caller wants applied before a scan starts, and named sets of them
//! to switch between. Everything here can also be done by setting fields on
//! [`ZondConfig`] directly; this saves a user retyping the same options.
//!
//! ```toml
//! [defaults]
//! effort = "balanced"
//! tcp_technique = "syn"
//!
//! [profiles.stealth]
//! tcp_technique = "fin"
//! max_probe_rate = 200
//!
//! [profiles.sweep]
//! effort = "single"
//! max_probe_rate = 50000
//! ```
//!
//! ## The engine never reads the filesystem on its own
//!
//! An embedder linking this crate into a service must not have its behaviour
//! changed by a file in the running account's home directory. So nothing here
//! happens unless a caller asks for it:
//!
//! - [`paths::user`] and [`paths::system`] compute where a settings file would
//!   live. They read environment variables and touch no disk.
//! - [`load`] opens a path the caller passes. [`read`] takes a reader, for a
//!   front end whose settings live in a database or an upload.
//! - [`provision`] creates a file, and only when there is none.
//! - [`Settings::apply_to`] changes a [`ZondConfig`] the caller owns.
//!
//! No scanner calls any of them.
//!
//! ## What a front end does at startup
//!
//! Four calls, in this order:
//!
//! ```no_run
//! use zond_engine::config::ZondConfig;
//! use zond_engine::import::settings;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Make sure the user has a file to edit. Creates one only if there is
//! //    none, and the template changes nothing.
//! let (path, outcome) = settings::provision_user()?;
//! if outcome.created() {
//!     println!("wrote a settings file to {}", path.display());
//! }
//!
//! // 2. Read whatever exists, layered, under the profile the user asked for.
//! let (settings, warnings) = settings::resolve(Some("stealth"))?;
//!
//! // 3. Report keys that were not understood.
//! for warning in &warnings {
//!     eprintln!("{warning}");
//! }
//!
//! // 4. Apply them to a configuration the caller owns, then override with
//! //    anything the user typed on top.
//! let mut config = ZondConfig::default();
//! settings.apply_to(&mut config);
//! # Ok(())
//! # }
//! ```
//!
//! An embedded engine typically skips this module and constructs [`ZondConfig`]
//! itself.
//!
//! ## TOML
//!
//! The on-disk form is TOML, which supports comments, so [`provision`] can write
//! a file that explains itself. [`Settings`] is an ordinary struct of `Option`
//! fields, so a front end keeping its settings in a database or in memory can
//! construct one directly.
//!
//! ## Every field that overrides is optional
//!
//! [`Settings`] holds `Option` for everything a later layer replaces, so unset
//! and set to the default value stay distinguishable. Otherwise a user file could
//! not override a system file back to a default.
//!
//! [`exclude`](Settings::exclude) and [`exclude_ports`](Settings::exclude_ports)
//! are a bare [`Exclusions`] and a bare [`PortSet`]: they accumulate across
//! layers, so an empty set simply adds nothing. See
//! [`overlay`](Settings::overlay) for why.
//!
//! Layers, each overriding the one before:
//!
//! ```text
//! ZondConfig::default()  →  system file  →  user file  →  named profile  →  the caller
//! ```
//!
//! ## No `Deserialize` on `ZondConfig`
//!
//! Deriving it would tie the file format to the struct layout, making every
//! field rename a breaking change for existing profiles. This module is the
//! hand-written boundary between them.
//!
//! ## What a settings file may say
//!
//! It sets numbers and chooses between named alternatives. There is no include
//! directive, no key naming a path that gets opened and no key naming a command,
//! since a file synced from a team repository is untrusted input.
//!
//! [`read`] and [`load`] refuse a document past [`MAX_DOCUMENT_BYTES`].

pub mod paths;

use std::collections::BTreeMap;
use std::fmt;
use std::io::BufRead;
use std::num::{NonZeroU8, NonZeroU32};
use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::Deserialize;

use crate::config::ZondConfig;
use crate::config::{ScanEffort, ScanPace, TimeoutScale};
use crate::model::exclusion::Exclusions;
use crate::model::ip::set::IpSet;
use crate::model::port::PortSet;
use crate::model::technique::{SctpScanTechnique, TcpScanTechnique};
use crate::transport::probe::SendMode;

/// The name a settings document is expected to have on disk.
pub const FILE_NAME: &str = "engine.toml";

/// The most bytes a settings document may be read from.
///
/// Fixed, unlike [`ImportLimits`](crate::import::ImportLimits) on a target
/// list: a settings file is a handful of keys, and [`TEMPLATE`] is under four
/// kilobytes with every key in it.
///
/// [`read`] and [`load`] hold the whole document and [`parse`] then holds two
/// parsed copies, so a file costs several times its own size in memory.
pub const MAX_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// The template [`provision`] writes.
///
/// Every key is present and commented out, so a freshly created file documents
/// the whole vocabulary and changes nothing. A test pins that.
pub const TEMPLATE: &str = include_str!("../../assets/settings/engine.toml");

/// What went wrong reading, writing or applying settings.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    /// The file could not be read or written.
    #[error("{path}: {source}")]
    Io {
        /// What was being opened.
        path: PathBuf,
        /// Why it failed.
        #[source]
        source: std::io::Error,
    },

    /// The document was not valid TOML, or a value was not of the right shape.
    #[error("settings are malformed: {0}")]
    Malformed(String),

    /// The document was longer than [`MAX_DOCUMENT_BYTES`].
    #[error("{path}: settings longer than the {limit} byte limit")]
    TooLarge {
        /// What was being read.
        path: PathBuf,
        /// The limit it passed.
        limit: u64,
    },

    /// A profile was asked for that the document does not define.
    #[error("no profile named '{wanted}'; this document defines: {}",
        if .available.is_empty() { "none".to_string() } else { .available.join(", ") })]
    UnknownProfile {
        /// The name that was asked for.
        wanted: String,
        /// The names that would have worked.
        available: Vec<String>,
    },

    /// No settings path could be computed for this host.
    #[error("no settings directory could be located for this user")]
    NoPath,
}

/// Whether [`provision`] had to create the file.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Provisioned {
    /// The file already existed and was left exactly as it was.
    Existed,
    /// The file did not exist and the commented template was written.
    Created,
}

impl Provisioned {
    /// Whether a file was written.
    pub fn created(self) -> bool {
        matches!(self, Provisioned::Created)
    }
}

/// Something a document said that this build did not understand.
///
/// Silently ignoring a misspelled `max_probe_rate` would run a scan at a rate
/// the user believes they changed. Making it fatal would stop an older engine
/// from reading a profile written for a newer one. So the caller gets these and
/// decides: a CLI prints them, a CI harness might treat them as failures.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SettingsWarning {
    /// The key, qualified by the table it appeared in.
    pub key: String,
    /// The closest key this build does know, when one is close enough to be
    /// worth suggesting.
    pub suggestion: Option<&'static str>,
}

impl fmt::Display for SettingsWarning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.suggestion {
            Some(suggestion) => {
                write!(
                    f,
                    "unknown setting '{}'; did you mean '{suggestion}'?",
                    self.key
                )
            }
            None => write!(f, "unknown setting '{}'", self.key),
        }
    }
}

/// A settings document, and everything in it this build did not recognise.
#[non_exhaustive]
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The document.
    pub document: SettingsDocument,
    /// Keys this build does not know.
    pub warnings: Vec<SettingsWarning>,
}

/// A whole settings document: the defaults, and the profiles that override
/// them.
#[non_exhaustive]
#[derive(Debug, Clone, Default, Deserialize)]
pub struct SettingsDocument {
    /// Applied to every scan, before any profile.
    #[serde(default)]
    pub defaults: Settings,
    /// Named sets of overrides. Ordered by name so two runs listing them agree.
    #[serde(default)]
    pub profiles: BTreeMap<String, Settings>,
}

impl SettingsDocument {
    /// The settings for `profile`, layered onto the document's defaults.
    ///
    /// `None` asks for the defaults alone. A name the document does not define is
    /// an error listing the names that would have worked, so asking for `stealth`
    /// cannot quietly produce a full-rate scan.
    pub fn resolve(&self, profile: Option<&str>) -> Result<Settings, SettingsError> {
        let mut settings = self.defaults.clone();

        if let Some(wanted) = profile {
            let Some(overrides) = self.profiles.get(wanted) else {
                return Err(SettingsError::UnknownProfile {
                    wanted: wanted.to_string(),
                    available: self.profiles.keys().cloned().collect(),
                });
            };
            settings.overlay(overrides);
        }

        Ok(settings)
    }

    /// The profile names this document defines, in order.
    pub fn profile_names(&self) -> impl Iterator<Item = &str> {
        self.profiles.keys().map(String::as_str)
    }
}

/// One layer of settings. Every field is optional; see the module
/// documentation for why.
///
/// Mirrors the fields of [`ZondConfig`] worth setting once and keeping, which is
/// not all of them. A document may narrow a scan but not widen one:
///
/// - **`segment_sweep` is missing.** It follows from the target expression the
///   user typed, and a file must not turn a single-host scan into a segment
///   sweep.
/// - **`exclude` is present.** It only ever removes packets from the wire, and
///   gives an administrator a place for ranges that must never be scanned.
///   Layers are unioned; see [`overlay`](Self::overlay).
/// - **`listen_only_ports` is missing.** That set keeps a scan from making every
///   printer it finds print its probes, so shrinking it widens what a scan
///   sends. Any key added for it may only add ports, unioned like `exclude`.
///   Clearing it is the caller's decision, made in code or for one run.
/// - **Nothing about presentation is here.** How a scan is displayed belongs to
///   the program displaying it, in a file of its own.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Forbids the scan from generating DNS traffic.
    pub no_dns: Option<bool>,
    /// Masks hostnames and hardware addresses in output.
    pub redact: Option<bool>,
    /// How raw probes are placed on the wire.
    #[serde(deserialize_with = "de_send_mode")]
    pub send_mode: Option<SendMode>,
    /// The fastest routed discovery may probe, in probes per second. Refused if
    /// zero.
    #[serde(deserialize_with = "de_probe_rate")]
    pub max_probe_rate: Option<NonZeroU32>,
    /// The slowest a scan may settle at, in probes per second. Refused if zero.
    #[serde(deserialize_with = "de_min_probe_rate")]
    pub min_probe_rate: Option<NonZeroU32>,
    /// The shortest gap between two probes at one host, in whole milliseconds.
    /// Refused if zero.
    #[serde(deserialize_with = "de_host_gap")]
    pub host_probe_interval: Option<Duration>,
    /// The shortest gap between any two probes, in whole milliseconds. Refused
    /// if zero.
    #[serde(deserialize_with = "de_scan_gap")]
    pub probe_interval: Option<Duration>,
    /// How long a scan may spend on one host, in whole seconds. Refused if
    /// zero.
    #[serde(deserialize_with = "de_timeout")]
    pub host_timeout: Option<Duration>,
    /// How long the whole scan may run, in whole seconds. Refused if zero.
    #[serde(deserialize_with = "de_timeout")]
    pub scan_timeout: Option<Duration>,
    /// Which segment a TCP port probe carries.
    #[serde(deserialize_with = "de_technique")]
    pub tcp_technique: Option<TcpScanTechnique>,
    /// Which chunk an SCTP port probe carries.
    #[serde(deserialize_with = "de_sctp_technique")]
    pub sctp_technique: Option<SctpScanTechnique>,
    /// How hard the scan tries before accepting silence as an answer.
    #[serde(deserialize_with = "de_effort")]
    pub effort: Option<ScanEffort>,
    /// How gently the scan treats the network, as a preset over the gaps and
    /// the patience.
    ///
    /// Applied before every other key of its layer, so a gap set beside it
    /// wins. See [`ScanPace::apply_to`] for what each level writes and why a
    /// slow one never loosens a gap already set.
    #[serde(deserialize_with = "de_pace")]
    pub pace: Option<ScanPace>,
    /// Replaces the attempt budget. One disables retransmission; zero is
    /// refused.
    #[serde(deserialize_with = "de_max_attempts")]
    pub max_attempts: Option<NonZeroU8>,
    /// Multiplies how long the scan is willing to wait. Refused unless positive
    /// and finite.
    #[serde(deserialize_with = "de_timeout_scale")]
    pub timeout_scale: Option<TimeoutScale>,
    /// Whether a host that answers nothing may have its probe budget cut.
    pub dampen_silent_hosts: Option<bool>,
    /// Whether to establish everything each TLS port accepts, beyond what one
    /// handshake negotiated.
    pub tls_enumeration: Option<bool>,
    /// The ports a scan covers when the caller names none.
    ///
    /// Held as written in the [`PortSet`] grammar; [`ports`](Self::ports)
    /// parses it.
    pub default_ports: Option<String>,
    /// Addresses no scan reading this document may probe.
    ///
    /// Written as a list of literal addresses, ranges and CIDR blocks:
    ///
    /// ```toml
    /// exclude = ["198.51.100.0/24", "192.0.2.10-20", "2001:db8::/64"]
    /// ```
    ///
    /// Parsed when the document is read, and a malformed entry is a document
    /// error. A malformed [`default_ports`](Self::default_ports) only degrades
    /// to the built-in list, but a malformed exclusion degrading the same way
    /// would silently scan the range it was meant to protect.
    ///
    /// Names and keywords are refused: `lan` and `db.internal` can mean
    /// something different on every machine and every lookup. For an exclusion
    /// typed at the moment it is used,
    /// [`resolve::for_exclusion`](crate::resolve::for_exclusion) takes the full
    /// grammar.
    #[serde(deserialize_with = "de_exclusions")]
    pub exclude: Exclusions,
    /// Ports no scan reading this document may probe on any target.
    ///
    /// Written as the port specification a scan takes, with the same `u:` and
    /// `s:` qualifiers:
    ///
    /// ```toml
    /// exclude_ports = "9100-9107, u:161"
    /// ```
    ///
    /// Parsed when the document is read and unioned across layers, for the
    /// reasons [`exclude`](Self::exclude) is. See
    /// [`ZondConfig::excluded_ports`] for what it holds a scan to.
    #[serde(deserialize_with = "de_exclude_ports")]
    pub exclude_ports: PortSet,
}

impl Settings {
    /// Settings that change nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes every value `other` sets, leaving the rest alone.
    ///
    /// A later layer speaks only about the keys it sets.
    pub fn overlay(&mut self, other: &Settings) {
        macro_rules! take {
            ($($field:ident),+ $(,)?) => {
                $(if other.$field.is_some() {
                    self.$field = other.$field.clone();
                })+
            };
        }

        take!(
            no_dns,
            redact,
            send_mode,
            max_probe_rate,
            min_probe_rate,
            host_probe_interval,
            probe_interval,
            host_timeout,
            scan_timeout,
            tcp_technique,
            sctp_technique,
            effort,
            pace,
            max_attempts,
            timeout_scale,
            dampen_silent_hosts,
            tls_enumeration,
            default_ports,
        );

        // The exclusions accumulate: a later layer overriding them would let a
        // user's file drop a range an administrator excluded system-wide.
        // Unioning can only make a scan smaller.
        self.exclude.extend(&other.exclude);
        self.exclude_ports = self.exclude_ports.union(&other.exclude_ports);
    }

    /// The default port set this document names, if it names one.
    ///
    /// Parsed here, not at load, so a document still loads when this key is
    /// wrong and the caller reports it. A specification naming no ports is
    /// malformed, since a scan taking the default would scan nothing.
    pub fn ports(&self) -> Option<Result<PortSet, SettingsError>> {
        self.default_ports.as_deref().map(|spec| {
            PortSet::parse_scan(spec).map_err(|error| {
                SettingsError::Malformed(format!("default_ports = '{spec}': {error}"))
            })
        })
    }

    /// Applies every value this sets to `config`, leaving the rest as it was.
    pub fn apply_to(&self, config: &mut ZondConfig) {
        // First, so the keys below override what the pace wrote.
        if let Some(pace) = self.pace {
            pace.apply_to(config);
        }
        if let Some(value) = self.no_dns {
            config.no_dns = value;
        }
        if let Some(value) = self.redact {
            config.redact = value;
        }
        if let Some(value) = self.send_mode {
            config.send_mode = value;
        }
        if self.max_probe_rate.is_some() {
            config.max_probe_rate = self.max_probe_rate;
        }
        if self.min_probe_rate.is_some() {
            config.min_probe_rate = self.min_probe_rate;
        }
        if self.host_probe_interval.is_some() {
            config.host_probe_interval = self.host_probe_interval;
        }
        if self.probe_interval.is_some() {
            config.probe_interval = self.probe_interval;
        }
        if self.host_timeout.is_some() {
            config.host_timeout = self.host_timeout;
        }
        if self.scan_timeout.is_some() {
            config.scan_timeout = self.scan_timeout;
        }
        if let Some(value) = self.tcp_technique {
            config.tcp_technique = value;
        }
        if let Some(value) = self.sctp_technique {
            config.sctp_technique = value;
        }
        if let Some(value) = self.effort {
            config.retry.effort = value;
        }
        if self.max_attempts.is_some() {
            config.retry.max_attempts = self.max_attempts;
        }
        if self.timeout_scale.is_some() {
            config.retry.timeout_scale = self.timeout_scale;
        }
        if let Some(value) = self.dampen_silent_hosts {
            config.retry.dampen_silent_hosts = value;
        }
        if let Some(value) = self.tls_enumeration {
            config.tls_enumeration = value;
        }
        // Added to what the configuration already forbids, for the reason
        // `overlay` gives, so neither order of applying loses an exclusion.
        config.exclusions.extend(&self.exclude);
        config.excluded_ports = config.excluded_ports.union(&self.exclude_ports);
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Every key [`Settings`] understands, for recognising one and for suggesting a
/// correction.
///
/// A field added to [`Settings`] must be added here and in [`TEMPLATE`], or a
/// document setting it is warned about while the value is applied.
/// `the_template_documents_every_key_and_no_others` checks this list against
/// the template; checking either against the struct is by hand.
const KNOWN_KEYS: [&str; 20] = [
    "exclude",
    "exclude_ports",
    "no_dns",
    "redact",
    "send_mode",
    "max_probe_rate",
    "min_probe_rate",
    "host_probe_interval",
    "probe_interval",
    "host_timeout",
    "scan_timeout",
    "tcp_technique",
    "sctp_technique",
    "effort",
    "pace",
    "max_attempts",
    "timeout_scale",
    "dampen_silent_hosts",
    "tls_enumeration",
    "default_ports",
];

/// Reads a settings document from anywhere.
///
/// Opens nothing, for a front end whose settings live in a database, an upload
/// or a string.
pub fn read(input: &mut dyn BufRead) -> Result<Loaded, SettingsError> {
    read_bounded(input, &PathBuf::from("<reader>"))
}

/// Reads at most [`MAX_DOCUMENT_BYTES`] from `input`, naming `path` if it
/// refuses.
///
/// Bounded during the read, as [`crate::import::list`] bounds a line, so an
/// endless input is never held in memory. One byte past the ceiling is read so
/// that a document exactly at it is accepted.
fn read_bounded(input: &mut dyn BufRead, path: &Path) -> Result<Loaded, SettingsError> {
    use std::io::Read as _;

    let mut text = String::new();
    let read = std::io::Read::take(input, MAX_DOCUMENT_BYTES.saturating_add(1))
        .read_to_string(&mut text)
        .map_err(|source| SettingsError::Io {
            path: path.to_path_buf(),
            source,
        })?;

    if read as u64 > MAX_DOCUMENT_BYTES {
        return Err(SettingsError::TooLarge {
            path: path.to_path_buf(),
            limit: MAX_DOCUMENT_BYTES,
        });
    }

    parse(&text)
}

/// Reads a settings document from a path.
///
/// The only function in this module that opens a file for reading, and only
/// the one it was handed.
pub fn load(path: &Path) -> Result<Loaded, SettingsError> {
    let file = std::fs::File::open(path).map_err(|source| SettingsError::Io {
        path: path.to_path_buf(),
        source,
    })?;

    read_bounded(&mut std::io::BufReader::new(file), path)
}

/// Parses a document and collects the keys this build does not know.
pub fn parse(text: &str) -> Result<Loaded, SettingsError> {
    // Parsed twice: the untyped pass finds the keys the typed one ignores.
    let raw: toml::Table = text
        .parse()
        .map_err(|error: toml::de::Error| SettingsError::Malformed(error.to_string()))?;

    let document: SettingsDocument = toml::from_str(text)
        .map_err(|error: toml::de::Error| SettingsError::Malformed(error.to_string()))?;

    let mut warnings = Vec::new();
    collect_warnings(&raw, &mut warnings);

    Ok(Loaded { document, warnings })
}

/// Walks the untyped document for keys no layer understands.
fn collect_warnings(raw: &toml::Table, warnings: &mut Vec<SettingsWarning>) {
    for (table, value) in raw {
        match table.as_str() {
            "defaults" => warn_unknown_keys("defaults", value, warnings),
            "profiles" => {
                let Some(profiles) = value.as_table() else {
                    continue;
                };
                for (name, settings) in profiles {
                    warn_unknown_keys(&format!("profiles.{name}"), settings, warnings);
                }
            }
            other => warnings.push(SettingsWarning {
                key: other.to_string(),
                suggestion: nearest("defaults", other).or_else(|| nearest("profiles", other)),
            }),
        }
    }
}

/// Reports the keys of one settings table that this build does not know.
fn warn_unknown_keys(table: &str, value: &toml::Value, warnings: &mut Vec<SettingsWarning>) {
    let Some(settings) = value.as_table() else {
        return;
    };

    for key in settings.keys() {
        if KNOWN_KEYS.contains(&key.as_str()) {
            continue;
        }
        warnings.push(SettingsWarning {
            key: format!("{table}.{key}"),
            // The nearest key, not the first close enough, so `no_dn`
            // suggests `no_dns`.
            suggestion: KNOWN_KEYS
                .iter()
                .copied()
                .map(|known| (edit_distance(key, known), known))
                .filter(|(distance, _)| *distance <= 2)
                .min_by_key(|(distance, _)| *distance)
                .map(|(_, known)| known),
        });
    }
}

/// The nearest of a single candidate, if it is near enough to suggest.
fn nearest(candidate: &'static str, written: &str) -> Option<&'static str> {
    (edit_distance(written, candidate) <= 2).then_some(candidate)
}

/// Levenshtein distance, bounded by the length of the shorter word.
///
/// Only run against a handful of short keys, so the simple two-row
/// implementation suffices.
fn edit_distance(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();

    let mut previous: Vec<usize> = (0..=b.len()).collect();
    let mut current = vec![0usize; b.len() + 1];

    for (i, left) in a.iter().enumerate() {
        current[0] = i + 1;
        for (j, right) in b.iter().enumerate() {
            let substitution = previous[j] + usize::from(left != right);
            current[j + 1] = substitution.min(previous[j + 1] + 1).min(current[j] + 1);
        }
        std::mem::swap(&mut previous, &mut current);
    }

    previous[b.len()]
}

// ---------------------------------------------------------------------------
// Provisioning
// ---------------------------------------------------------------------------

/// Creates a settings file at `path` if there is not one already.
///
/// Cannot cost anybody their configuration:
///
/// - **It never overwrites.** The file is created with `create_new`, which fails
///   atomically if anything is already there, so two racing processes cannot
///   both decide the file was missing.
/// - **It never edits.** An existing file is not read, reformatted or extended,
///   which would lose its comments and ordering.
/// - **What it writes changes nothing.** [`TEMPLATE`] has every key commented
///   out. A test pins that.
///
/// Parent directories are created as needed. On Unix the directory is created
/// `0700` and the file `0600`, since a settings file records which networks
/// somebody scans.
///
/// Under `sudo`, the file and every directory this call creates inside the
/// invoking user's home are given to that user; owned by root, a `0700`
/// directory and `0600` file would be unusable to them. A file or directory on
/// the way that an earlier elevated run left to root is given back the same
/// way. Anything outside that home, the system file included, stays root's.
pub fn provision(path: &Path) -> Result<Provisioned, SettingsError> {
    provision_document(path, TEMPLATE)
}

/// [`provision`], writing `document` in place of the engine's template.
///
/// For a front end keeping its own settings file beside the engine's: the same
/// guarantees and the same ownership under `sudo`. `document` should change
/// nothing about a run when first written, as [`TEMPLATE`] does.
pub fn provision_document(path: &Path, document: &str) -> Result<Provisioned, SettingsError> {
    if let Some(parent) = path.parent() {
        let created = create_directory(parent)?;
        crate::journal::ownership::hand_over(parent, &created);
    }

    match create_file(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(document.as_bytes())
                .map_err(|source| SettingsError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            crate::journal::ownership::give_open(&file, path);
            Ok(Provisioned::Created)
        }
        // An existing file is success.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            crate::journal::ownership::reclaim_file(path);
            Ok(Provisioned::Existed)
        }
        Err(source) => Err(SettingsError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Creates the settings file, `0600` on Unix and refusing a name that exists.
///
/// Opened as a journal's files are, so under `sudo` a link leading out of the
/// invoking user's home is refused; see `journal::ownership::Place`.
#[cfg(unix)]
fn create_file(path: &Path) -> std::io::Result<std::fs::File> {
    crate::journal::ownership::Place::of(path)?
        .open(libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL, 0o600)
}

/// [`create_file`] where there is no mode to set and no `sudo`.
#[cfg(not(unix))]
fn create_file(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
}

/// Creates a directory and its parents, with restrictive permissions on Unix,
/// and returns the directories it created.
fn create_directory(path: &Path) -> Result<Vec<PathBuf>, SettingsError> {
    crate::journal::ownership::create_missing(path, Some(0o700)).map_err(|source| {
        SettingsError::Io {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// Creates the user's settings file if there is not one, and reports where it
/// is.
///
/// One call at startup that leaves the user with a file to edit.
pub fn provision_user() -> Result<(PathBuf, Provisioned), SettingsError> {
    let path = paths::user().ok_or(SettingsError::NoPath)?;
    let outcome = provision(&path)?;
    Ok((path, outcome))
}

/// Loads the settings a caller should run under, from the files that exist.
///
/// Reads the system file then the user file, skipping either if it is not there,
/// layers them in that order, then applies `profile`. A file that exists but
/// cannot be parsed is an error, so a scan never runs without settings the user
/// believes they wrote.
///
/// Returns the resolved settings and every warning from every file. Nothing is
/// applied anywhere; hand the result to [`Settings::apply_to`].
pub fn resolve(profile: Option<&str>) -> Result<(Settings, Vec<SettingsWarning>), SettingsError> {
    let mut settings = Settings::new();
    let mut warnings = Vec::new();
    let mut found_profile = profile.is_none();
    // Gathered across every file, so an unknown profile error lists them all.
    let mut available: Vec<String> = Vec::new();

    for path in paths::layered() {
        if !path.exists() {
            continue;
        }

        let loaded = load(&path)?;
        warnings.extend(loaded.warnings);

        settings.overlay(&loaded.document.defaults);

        for name in loaded.document.profile_names() {
            if !available.iter().any(|known| known == name) {
                available.push(name.to_string());
            }
        }

        if let Some(wanted) = profile
            && let Some(overrides) = loaded.document.profiles.get(wanted)
        {
            settings.overlay(overrides);
            found_profile = true;
        }
    }

    if !found_profile {
        available.sort();
        return Err(SettingsError::UnknownProfile {
            wanted: profile.unwrap_or_default().to_string(),
            available,
        });
    }

    Ok((settings, warnings))
}

// ---------------------------------------------------------------------------
// Deserialization of the fields that are named alternatives
// ---------------------------------------------------------------------------

/// Reads a value written as one of a fixed set of names.
///
/// The error names what was written and what would have worked, so
/// `tcp_technique = "stealth"` fails at load.
pub(super) fn de_named<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: fmt::Display,
{
    let Some(text) = Option::<String>::deserialize(deserializer)? else {
        return Ok(None);
    };
    text.parse().map(Some).map_err(serde::de::Error::custom)
}

/// Reads a [`SendMode`] by name, through [`de_named`].
fn de_send_mode<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<SendMode>, D::Error> {
    de_named(d)
}

/// [`de_send_mode`] for the TCP technique.
fn de_technique<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<TcpScanTechnique>, D::Error> {
    de_named(d)
}

/// [`de_send_mode`] for the SCTP technique.
fn de_sctp_technique<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<SctpScanTechnique>, D::Error> {
    de_named(d)
}

/// [`de_send_mode`] for the scan effort.
fn de_effort<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<ScanEffort>, D::Error> {
    de_named(d)
}

/// [`de_send_mode`] for the scan pace.
fn de_pace<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<ScanPace>, D::Error> {
    de_named(d)
}

/// Reads `max_probe_rate`, refusing a ceiling of zero.
///
/// The engine would otherwise discard an unusable value where the schedule is
/// built and still record it in the report as applied.
fn de_probe_rate<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<NonZeroU32>, D::Error> {
    let Some(rate) = Option::<u32>::deserialize(d)? else {
        return Ok(None);
    };
    NonZeroU32::new(rate).map(Some).ok_or_else(|| {
        serde::de::Error::custom(
            "max_probe_rate = 0: a ceiling of zero probes per second is not a slower scan \
             but no scan. Remove the key to leave each scanner its own pacing.",
        )
    })
}

/// Reads `min_probe_rate`, refusing a floor of zero.
///
/// A floor of zero means no floor, which leaving the key out already says, and
/// accepting it would record a bound in the report that bound nothing.
fn de_min_probe_rate<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<NonZeroU32>, D::Error> {
    let Some(rate) = Option::<u32>::deserialize(d)? else {
        return Ok(None);
    };
    NonZeroU32::new(rate).map(Some).ok_or_else(|| {
        serde::de::Error::custom(
            "min_probe_rate = 0: a floor of zero probes per second is the absence of a floor. \
             Remove the key to let each scanner settle where it will.",
        )
    })
}

/// Reads a wall-clock budget written in whole seconds, refusing zero.
///
/// Zero would expire before the first probe.
fn de_timeout<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    let Some(seconds) = Option::<u64>::deserialize(d)? else {
        return Ok(None);
    };
    if seconds == 0 {
        return Err(serde::de::Error::custom(
            "a timeout of 0 seconds expires before the first probe, which is a scan \
             that asks nothing. Remove the key to leave the scan unbounded.",
        ));
    }
    Ok(Some(Duration::from_secs(seconds)))
}

/// Reads a gap written in whole milliseconds, refusing zero.
///
/// Milliseconds because useful gaps are shorter than a second: ten probes a
/// second is a hundred milliseconds. Zero is refused for the reason
/// [`de_min_probe_rate`] refuses a floor of zero.
fn de_host_gap<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    de_millis("host_probe_interval", d)
}

/// Reads `probe_interval`, refusing a gap of zero.
fn de_scan_gap<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<Duration>, D::Error> {
    de_millis("probe_interval", d)
}

/// Reads a gap in whole milliseconds under `key`, refusing zero.
fn de_millis<'de, D: serde::Deserializer<'de>>(
    key: &str,
    d: D,
) -> Result<Option<Duration>, D::Error> {
    let Some(millis) = Option::<u64>::deserialize(d)? else {
        return Ok(None);
    };
    if millis == 0 {
        return Err(serde::de::Error::custom(format!(
            "{key} = 0: a gap of no time is the absence of a gap. \
             Remove the key to let each pass send as fast as its own pacing allows."
        )));
    }
    Ok(Some(Duration::from_millis(millis)))
}

/// Reads `max_attempts`, refusing a budget of zero.
fn de_max_attempts<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<NonZeroU8>, D::Error> {
    let Some(attempts) = Option::<u8>::deserialize(d)? else {
        return Ok(None);
    };
    NonZeroU8::new(attempts).map(Some).ok_or_else(|| {
        serde::de::Error::custom(
            "max_attempts = 0: a probe that is never sent is not a scan setting. \
             Write 1 for a single attempt with no retransmission.",
        )
    })
}

/// Reads `timeout_scale`, refusing anything no schedule can be built from.
fn de_timeout_scale<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<TimeoutScale>, D::Error> {
    let Some(scale) = Option::<f64>::deserialize(d)? else {
        return Ok(None);
    };
    TimeoutScale::new(scale).map(Some).ok_or_else(|| {
        serde::de::Error::custom(format!(
            "timeout_scale = {scale}: a scale multiplies how long the scan waits, \
             so it has to be a positive, finite number."
        ))
    })
}

/// Reads `exclude` as a list of address expressions, refusing anything the
/// document cannot settle by itself.
///
/// [`IpSet`]'s grammar takes only a literal address, an inclusive range or a
/// CIDR block, so a keyword or hostname is a parse failure. See
/// [`Settings::exclude`] for why.
fn de_exclusions<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Exclusions, D::Error> {
    let written = Vec::<String>::deserialize(d)?;

    let mut ips = IpSet::new();
    for expression in &written {
        let parsed: IpSet = expression.parse().map_err(|error| {
            serde::de::Error::custom(format!(
                "exclude = '{expression}': {error}. A settings file takes addresses, \
                 ranges and CIDR blocks; names and keywords such as 'lan' mean something \
                 different on every machine that reads the file and are not accepted here."
            ))
        })?;
        for range in parsed.v4() {
            ips.push_v4_range(*range);
        }
        for range in parsed.v6() {
            ips.push_v6_range(*range);
        }
    }

    Ok(Exclusions::new(ips))
}

/// Reads `exclude_ports` as a port specification, refusing one that does not
/// parse. See [`Settings::exclude_ports`] for why.
fn de_exclude_ports<'de, D: serde::Deserializer<'de>>(d: D) -> Result<PortSet, D::Error> {
    let written = String::deserialize(d)?;
    PortSet::try_from(written.as_str())
        .map_err(|error| serde::de::Error::custom(format!("exclude_ports = '{written}': {error}")))
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

    fn document(text: &str) -> Loaded {
        parse(text).expect("the document parses")
    }

    /// A value the engine cannot honour is refused where the document is read,
    /// so it is never discarded later and still reported as applied.
    #[test]
    fn a_setting_the_engine_could_not_honour_is_refused_by_name() {
        for (document, expected) in [
            ("[defaults]\nmax_probe_rate = 0\n", "max_probe_rate"),
            ("[defaults]\nmin_probe_rate = 0\n", "min_probe_rate"),
            (
                "[defaults]\nhost_probe_interval = 0\n",
                "host_probe_interval",
            ),
            ("[defaults]\nprobe_interval = 0\n", "probe_interval"),
            ("[defaults]\nmax_attempts = 0\n", "max_attempts"),
            ("[defaults]\ntimeout_scale = 0.0\n", "timeout_scale"),
            ("[defaults]\ntimeout_scale = -1.5\n", "timeout_scale"),
            ("[defaults]\ntimeout_scale = nan\n", "timeout_scale"),
        ] {
            let refused = read(&mut document.as_bytes()).expect_err(document);
            let message = refused.to_string();
            assert!(
                message.contains(expected),
                "{document:?} was refused without naming {expected}: {message}"
            );
        }
    }

    /// The smallest usable values still read.
    #[test]
    fn the_smallest_usable_values_are_accepted() {
        let mut document = &b"[defaults]\nmax_probe_rate = 1\nmin_probe_rate = 1\nmax_attempts = 1\ntimeout_scale = 0.001\n"[..];
        let loaded = read(&mut document).expect("the smallest usable values are settings");

        let settings = loaded.document.resolve(None).expect("resolves");
        assert_eq!(settings.max_probe_rate, NonZeroU32::new(1));
        assert_eq!(settings.min_probe_rate, NonZeroU32::new(1));
        assert_eq!(settings.max_attempts, NonZeroU8::new(1));
        assert_eq!(settings.timeout_scale.map(TimeoutScale::get), Some(0.001));
    }

    /// Exclusions accumulate across every layer: the administrator's range,
    /// the user's and the profile's all hold.
    #[test]
    fn every_layer_adds_its_exclusions_and_none_replaces_another() {
        let mut administrator = document(
            r#"
            [defaults]
            exclude = ["198.51.100.0/24"]

            [profiles.audit]
            exclude = ["203.0.113.0/24"]
            "#,
        )
        .document;

        let user = document(
            r#"
            [defaults]
            exclude = ["192.0.2.50"]
            "#,
        )
        .document;

        administrator.defaults.overlay(&user.defaults);
        let settings = administrator.resolve(Some("audit")).expect("the profile");

        let mut config = ZondConfig::default();
        settings.apply_to(&mut config);

        for excluded in ["198.51.100.7", "192.0.2.50", "203.0.113.1"] {
            assert!(
                config
                    .exclusions
                    .excludes(&excluded.parse().expect("literal")),
                "{excluded} was named by a layer and must still be excluded"
            );
        }
        assert!(
            !config
                .exclusions
                .excludes(&"192.0.2.51".parse().expect("literal"))
        );
    }

    /// No settings document takes a port off the listen-only list, at any
    /// layer, under any likely key name. A key added for it that replaced the
    /// set would fail here.
    #[test]
    fn no_document_can_take_a_port_off_the_listen_only_list() {
        for (text, profile) in [
            ("[defaults]\nlisten_only_ports = []\n", None),
            ("[defaults]\nlisten_only_ports = [9100]\n", None),
            ("[profiles.p]\nlisten_only_ports = []\n", Some("p")),
            ("[defaults]\nprobe_print_ports = true\n", None),
        ] {
            let Ok(loaded) = parse(text) else {
                // A refused document keeps the list whole.
                continue;
            };
            let settings = loaded.document.resolve(profile).expect("resolves");
            let mut config = ZondConfig::default();
            settings.apply_to(&mut config);

            for port in crate::config::RAW_PRINT_PORTS {
                assert!(
                    config.listen_only_ports.contains(port),
                    "{text:?} took {port} off the list"
                );
            }
        }
    }

    /// Applying a document adds to what the caller already forbade.
    #[test]
    fn applying_a_document_keeps_the_exclusions_the_caller_already_had() {
        let mut from_the_command_line = IpSet::new();
        from_the_command_line.insert_range("203.0.113.0/24".parse().expect("a valid range"));

        let mut config = ZondConfig {
            exclusions: Exclusions::new(from_the_command_line),
            ..Default::default()
        };

        document(
            r#"
            [defaults]
            exclude = ["198.51.100.0/24"]
            "#,
        )
        .document
        .defaults
        .apply_to(&mut config);

        assert!(
            config
                .exclusions
                .excludes(&"203.0.113.4".parse().expect("literal"))
        );
        assert!(
            config
                .exclusions
                .excludes(&"198.51.100.7".parse().expect("literal"))
        );
    }

    /// A malformed exclusion, `lan` or a hostname stops the document from
    /// loading.
    #[test]
    fn a_malformed_exclusion_refuses_the_document() {
        for written in ["lan", "db.internal", "198.51.100.0/33"] {
            let error = parse(&format!(
                r#"
                [defaults]
                exclude = ["{written}"]
                "#
            ))
            .expect_err("the document must not load");

            assert!(
                error.to_string().contains(written),
                "the error names what was written: {error}"
            );
        }
    }

    /// Excluded ports accumulate across every layer and onto what the caller
    /// already excluded, and one that does not parse stops the document.
    #[test]
    fn excluded_ports_add_up_across_layers_and_a_malformed_one_refuses_the_document() {
        let mut system = document(
            r#"
            [defaults]
            exclude_ports = "9100-9107"
            "#,
        )
        .document;
        let user = document(
            r#"
            [defaults]
            exclude_ports = "22, u:161"
            "#,
        )
        .document;
        system.defaults.overlay(&user.defaults);

        let mut config = ZondConfig {
            excluded_ports: "3389".try_into().expect("a port"),
            ..ZondConfig::default()
        };
        system
            .resolve(None)
            .expect("the defaults")
            .apply_to(&mut config);

        assert_eq!(config.excluded_ports.to_string(), "22,3389,9100-9107,u:161");

        for written in ["80-20", "http", "70000"] {
            let error = parse(&format!("[defaults]\nexclude_ports = \"{written}\"\n"))
                .expect_err("the document must not load");
            assert!(
                error.to_string().contains(written),
                "the error names what was written: {error}"
            );
        }
    }

    /// A later file speaks only about the keys it mentions.
    #[test]
    fn a_later_layer_overrides_only_what_it_mentions() {
        let system = document(
            r#"
            [defaults]
            redact = true
            no_dns = true
            max_probe_rate = 1000
            "#,
        );
        let user = document(
            r#"
            [defaults]
            redact = false
            "#,
        );

        let mut settings = system.document.defaults.clone();
        settings.overlay(&user.document.defaults);

        assert_eq!(
            settings.redact,
            Some(false),
            "the user file spoke about this"
        );
        assert_eq!(settings.no_dns, Some(true), "and said nothing about this");
        assert_eq!(settings.max_probe_rate, NonZeroU32::new(1000));
    }

    #[test]
    fn a_profile_layers_onto_the_defaults() {
        let loaded = document(
            r#"
            [defaults]
            effort = "balanced"
            max_probe_rate = 20000
            no_dns = true

            [profiles.stealth]
            effort = "thorough"
            max_probe_rate = 200
            "#,
        );

        let defaults = loaded.document.resolve(None).expect("resolves");
        assert_eq!(defaults.effort, Some(ScanEffort::Balanced));
        assert_eq!(defaults.max_probe_rate, NonZeroU32::new(20000));

        let stealth = loaded.document.resolve(Some("stealth")).expect("resolves");
        assert_eq!(stealth.effort, Some(ScanEffort::Thorough));
        assert_eq!(stealth.max_probe_rate, NonZeroU32::new(200));
        assert_eq!(stealth.no_dns, Some(true), "inherited from the defaults");
    }

    /// A profile name the document does not define is an error listing the
    /// ones it does.
    #[test]
    fn an_unknown_profile_is_an_error_naming_the_ones_that_exist() {
        let loaded = document(
            r#"
            [profiles.stealth]
            effort = "thorough"

            [profiles.sweep]
            effort = "single"
            "#,
        );

        match loaded.document.resolve(Some("quiet")).expect_err("refused") {
            SettingsError::UnknownProfile { wanted, available } => {
                assert_eq!(wanted, "quiet");
                assert_eq!(available, vec!["stealth", "sweep"]);
            }
            other => panic!("expected an unknown profile, got {other:?}"),
        }
    }

    /// An unknown key is a warning, with a suggestion when one is close.
    #[test]
    fn an_unknown_key_is_reported_with_the_nearest_one_that_exists() {
        let loaded = document(
            r#"
            [defaults]
            max_probe_rat = 500
            invented_entirely = true

            [profiles.stealth]
            tcp_techniqu = "fin"
            "#,
        );

        assert_eq!(loaded.warnings.len(), 3, "{:?}", loaded.warnings);

        // Looked up by key: the order is sorted, which this module does not
        // promise.
        let find = |key: &str| {
            loaded
                .warnings
                .iter()
                .find(|warning| warning.key == key)
                .unwrap_or_else(|| panic!("no warning for {key}: {:?}", loaded.warnings))
        };

        assert_eq!(
            find("defaults.max_probe_rat").suggestion,
            Some("max_probe_rate")
        );
        assert_eq!(
            find("defaults.invented_entirely").suggestion,
            None,
            "nothing is close enough to this to be worth suggesting"
        );
        assert_eq!(
            find("profiles.stealth.tcp_techniqu").suggestion,
            Some("tcp_technique")
        );
    }

    /// A named alternative that does not exist fails at load.
    #[test]
    fn a_name_outside_the_set_is_refused_at_load_and_says_what_would_have_worked() {
        let error = parse(
            r#"
            [defaults]
            tcp_technique = "stealth"
            "#,
        )
        .expect_err("refused");

        let message = error.to_string();
        assert!(message.contains("stealth"), "{message}");
        assert!(message.contains("syn"), "the accepted names: {message}");
    }

    /// A key beside a pace overrides it, and the pace's other values still
    /// apply.
    #[test]
    fn a_pace_gives_way_to_the_keys_beside_it() {
        let loaded = document(
            r#"
            [defaults]
            probe_interval = 250
            pace = "sparing"
            "#,
        );

        let mut config = ZondConfig::default();
        loaded.document.defaults.apply_to(&mut config);

        assert_eq!(config.probe_interval, Some(Duration::from_millis(250)));
        assert_eq!(
            config.host_probe_interval,
            Some(Duration::from_millis(100)),
            "the pace's per-host gap, which the document left alone"
        );
    }

    /// Applying settings changes only the keys they set.
    #[test]
    fn applying_settings_changes_only_what_they_name() {
        let loaded = document(
            r#"
            [defaults]
            no_dns = true
            redact = true
            tcp_technique = "xmas"
            effort = "thorough"
            max_attempts = 5
            max_probe_rate = 750
            send_mode = "ethernet"
            "#,
        );

        let mut config = ZondConfig::default();
        let before_sweep = config.segment_sweep;
        loaded.document.defaults.apply_to(&mut config);

        assert!(config.no_dns);
        assert!(config.redact);
        assert_eq!(config.tcp_technique, TcpScanTechnique::Xmas);
        assert_eq!(config.retry.effort, ScanEffort::Thorough);
        assert_eq!(config.retry.max_attempts, NonZeroU8::new(5));
        assert_eq!(config.max_probe_rate, NonZeroU32::new(750));
        assert_eq!(config.send_mode, SendMode::Ethernet);
        assert_eq!(
            config.segment_sweep, before_sweep,
            "a file must not be able to turn a single-host scan into a segment sweep"
        );
    }

    /// A document that sets nothing changes nothing.
    #[test]
    fn an_empty_document_changes_no_configuration() {
        let loaded = document("");
        let mut config = ZondConfig::default();
        loaded.document.defaults.apply_to(&mut config);

        let untouched = ZondConfig::default();
        assert_eq!(config.no_dns, untouched.no_dns);
        assert_eq!(config.redact, untouched.redact);
        assert_eq!(config.tcp_technique, untouched.tcp_technique);
        assert_eq!(config.max_probe_rate, untouched.max_probe_rate);
        assert_eq!(config.retry.effort, untouched.retry.effort);
    }

    /// The template is entirely commented out, so creating a settings file
    /// changes no scan.
    #[test]
    fn the_provisioned_template_parses_and_changes_nothing() {
        let loaded = parse(TEMPLATE).expect("the shipped template is valid TOML");

        assert!(
            loaded.warnings.is_empty(),
            "the template names a key this build does not know: {:?}",
            loaded.warnings
        );
        assert_eq!(
            loaded.document.defaults,
            Settings::new(),
            "the template must set nothing"
        );

        let mut config = ZondConfig::default();
        loaded.document.defaults.apply_to(&mut config);
        assert_eq!(config.redact, ZondConfig::default().redact);
        assert_eq!(config.tcp_technique, ZondConfig::default().tcp_technique);
    }

    /// The template and [`KNOWN_KEYS`] name the same settings, both ways.
    ///
    /// The template must document every key this build reads, and nothing it
    /// ignores.
    #[test]
    fn the_template_documents_every_key_and_no_others() {
        let known: std::collections::BTreeSet<&str> = KNOWN_KEYS.into_iter().collect();

        let documented: std::collections::BTreeSet<&str> = TEMPLATE
            .lines()
            .filter_map(|line| {
                line.trim_start()
                    .strip_prefix('#')
                    .unwrap_or(line)
                    .split_once('=')
            })
            .map(|(key, _)| key.trim())
            .filter(|key| {
                !key.is_empty() && key.chars().all(|c| c.is_ascii_lowercase() || c == '_')
            })
            .collect();

        assert_eq!(
            known.difference(&documented).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "the template does not document a key this build reads"
        );
        assert_eq!(
            documented.difference(&known).collect::<Vec<_>>(),
            Vec::<&&str>::new(),
            "the template documents a key this build ignores"
        );
    }

    #[test]
    fn a_port_specification_is_parsed_when_asked_for_and_not_before() {
        let good = document(
            r#"
            [defaults]
            default_ports = "22,80,u:53"
            "#,
        );
        let ports = good
            .document
            .defaults
            .ports()
            .expect("names ports")
            .unwrap();
        assert!(ports.has_tcp(22));
        assert!(ports.has_udp(53));

        // A malformed specification does not stop the document loading.
        let bad = document(
            r#"
            [defaults]
            default_ports = "http"
            "#,
        );
        assert!(bad.document.defaults.ports().expect("names ports").is_err());
    }

    /// An empty `default_ports` would silently scan nothing, so it is
    /// malformed.
    #[test]
    fn a_default_port_specification_naming_nothing_is_refused() {
        let empty = document(
            r#"
            [defaults]
            default_ports = ""
            "#,
        );
        let error = empty
            .document
            .defaults
            .ports()
            .expect("names ports")
            .expect_err("an empty default");
        assert!(error.to_string().contains("names no ports"), "{error}");
    }

    #[test]
    fn a_document_that_is_not_toml_is_refused() {
        assert!(matches!(
            parse("this is not = = toml"),
            Err(SettingsError::Malformed(_))
        ));
    }

    /// A second call leaves the file exactly as it was, including the user's
    /// edits.
    #[test]
    fn provisioning_creates_once_and_never_overwrites() {
        let dir = std::env::temp_dir().join(format!("zond-settings-{}", std::process::id()));
        let path = dir.join(FILE_NAME);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(provision(&path).expect("creates"), Provisioned::Created);
        assert!(path.exists());

        // Stand in for a user editing the file they were given.
        std::fs::write(&path, "[defaults]\nredact = true\n").expect("writes");

        assert_eq!(
            provision(&path).expect("finds"),
            Provisioned::Existed,
            "a second call must not report having created anything"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("reads"),
            "[defaults]\nredact = true\n",
            "provisioning overwrote a file somebody had edited"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The startup sequence a front end runs, in a temporary directory:
    /// provision, find it there the second time, read it back, apply it.
    #[test]
    fn provisioning_then_loading_produces_settings_that_change_nothing() {
        let dir = std::env::temp_dir().join(format!("zond-startup-{}", std::process::id()));
        let path = dir.join(FILE_NAME);
        let _ = std::fs::remove_dir_all(&dir);

        assert_eq!(provision(&path).expect("creates"), Provisioned::Created);
        assert_eq!(provision(&path).expect("finds"), Provisioned::Existed);

        let loaded = load(&path).expect("the file it just wrote is readable");
        assert!(loaded.warnings.is_empty());

        let settings = loaded.document.resolve(None).expect("resolves");
        let mut config = ZondConfig::default();
        settings.apply_to(&mut config);

        let untouched = ZondConfig::default();
        assert_eq!(config.redact, untouched.redact);
        assert_eq!(config.tcp_technique, untouched.tcp_technique);
        assert_eq!(config.retry.effort, untouched.retry.effort);
        assert_eq!(config.max_probe_rate, untouched.max_probe_rate);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On Unix the file and directory are private to their owner.
    #[cfg(unix)]
    #[test]
    fn a_provisioned_file_is_readable_only_by_its_owner() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!("zond-modes-{}", std::process::id()));
        let path = dir.join(FILE_NAME);
        let _ = std::fs::remove_dir_all(&dir);

        provision(&path).expect("creates");

        let file = std::fs::metadata(&path).expect("stat").permissions().mode();
        let directory = std::fs::metadata(&dir).expect("stat").permissions().mode();

        assert_eq!(file & 0o077, 0, "the file is readable by somebody else");
        assert_eq!(
            directory & 0o077,
            0,
            "the directory is traversable by somebody else"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn edit_distance_is_the_ordinary_one() {
        assert_eq!(edit_distance("quiet", "quiet"), 0);
        assert_eq!(edit_distance("quie", "quiet"), 1);
        assert_eq!(edit_distance("max_probe_rat", "max_probe_rate"), 1);
        assert_eq!(edit_distance("", "abc"), 3);
    }
}
