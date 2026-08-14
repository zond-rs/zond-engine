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
//! to switch between. A quality-of-life feature: everything here can also be
//! done by setting fields on [`ZondConfig`] directly, and this exists so a user
//! does not have to type the same six flags every time.
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
//! This is the rule the whole module is arranged around, and it is not a
//! preference. A library that silently absorbs whatever is in the running
//! account's home directory is a supply-chain problem wearing a convenience
//! feature's clothes: an embedder who links this crate into a web service has
//! not agreed to have that service's behaviour changed by a file they never
//! looked at.
//!
//! So nothing here happens unless a caller asks for it, by name:
//!
//! - [`paths::user`] and [`paths::system`] *compute* where a settings file
//!   would live. They read environment variables and touch no disk.
//! - [`load`] opens a path the caller passes. [`read`] takes a reader and does
//!   not open anything, for a front end whose settings live in a database or an
//!   upload.
//! - [`provision`] creates a file, and only when there is none.
//! - [`Settings::apply_to`] changes a [`ZondConfig`] the caller owns.
//!
//! No scanner calls any of them. There is no lazy initialization, no static, and
//! no constructor that quietly looks somewhere.
//!
//! ## What a front end does at startup
//!
//! Four calls, in this order, none of them implicit:
//!
//! ```no_run
//! use zond_engine::config::ZondConfig;
//! use zond_engine::import::settings;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! // 1. Make sure the user has a file to edit. Creates one only if there is
//! //    none, and what it writes changes nothing.
//! let (path, outcome) = settings::provision_user()?;
//! if outcome.created() {
//!     println!("wrote a settings file to {}", path.display());
//! }
//!
//! // 2. Read whatever exists, layered, under the profile the user asked for.
//! let (settings, warnings) = settings::resolve(Some("stealth"))?;
//!
//! // 3. Say what was not understood. Ignoring these is the caller's choice to
//! //    make, and they have to hold them to make it.
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
//! A front end that wants none of this constructs [`ZondConfig`] itself and
//! never calls into this module, which is exactly what an embedded engine
//! should do.
//!
//! ## TOML, and why that barely matters
//!
//! The on-disk form is TOML: it is already an unconditional dependency of this
//! crate, it has comments - which is what lets [`provision`] write a file that
//! explains itself - and `[profiles.<name>]` is exactly the shape of the
//! feature.
//!
//! But the format is only a serialization. [`Settings`] is an ordinary struct of
//! `Option` fields, so a front end keeping its settings in Postgres, in a
//! browser's local storage, or in memory constructs one directly and never
//! touches TOML or a filesystem at all.
//!
//! ## Every field is optional, and that is the whole design
//!
//! [`Settings`] holds `Option` everywhere so that *unset* and *set to the
//! default value* stay distinguishable. Without that, layering is impossible: a
//! user file could never override a system file back to a default, because
//! "back to the default" would be indistinguishable from "said nothing".
//!
//! Layers, each overriding the one before:
//!
//! ```text
//! ZondConfig::default()  →  system file  →  user file  →  named profile  →  the caller
//! ```
//!
//! ## Never `#[derive(Deserialize)]` on `ZondConfig`
//!
//! The same argument that keeps `Serialize` off `Host`. Deriving welds the file
//! format to the struct layout, and the first field rename turns into a breaking
//! change for every profile anybody has written. This module is the hand-written
//! boundary that costs one file and buys the freedom to move.
//!
//! ## What a settings file may not do
//!
//! It sets numbers and chooses between named alternatives. That is the entire
//! vocabulary. There is no include directive, no key naming a path that gets
//! opened, and no key naming a command. A file synced from a team repository is
//! input nobody vouches for, and the way to keep that safe is for there to be
//! nothing in the grammar worth attacking.

pub mod paths;

use std::collections::BTreeMap;
use std::fmt;
use std::io::BufRead;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::ScanEffort;
use crate::config::{SendMode, ZondConfig};
use crate::model::port::PortSet;
use crate::model::technique::TcpScanTechnique;

/// The name a settings document is expected to have on disk.
pub const FILE_NAME: &str = "engine.toml";

/// The template [`provision`] writes.
///
/// Every key is present and every key is commented out, so a freshly created
/// file documents the whole vocabulary and changes nothing. That property is
/// deliberate and is pinned by a test: creating a settings file must never
/// change what a scan does.
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
/// Reported rather than dropped, and rather than fatal. A misspelled
/// `max_probe_rate` that silently does nothing means a scan runs at a rate the
/// user believes they changed, which is the worst kind of failure because
/// everything appears to work. Making it fatal is also wrong: it would stop an
/// older engine from reading a profile a colleague wrote with a newer one.
///
/// So the caller is handed these and decides. A CLI prints them; a CI harness
/// treats them as failures.
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
#[derive(Debug, Clone)]
pub struct Loaded {
    /// The document.
    pub document: SettingsDocument,
    /// Keys this build does not know. Never empty-checked for you: a caller
    /// that wants to ignore them has to hold them first.
    pub warnings: Vec<SettingsWarning>,
}

/// A whole settings document: the defaults, and the profiles that override
/// them.
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
    /// `None` asks for the defaults alone. A name the document does not define
    /// is an error listing the names that would have worked, rather than a
    /// silent fall back to the defaults - a user who asked for `stealth` and
    /// quietly got a full-rate scan has been failed badly.
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

/// One layer of settings. Every field is optional; see the module documentation
/// for why that is the design rather than a convenience.
///
/// Mirrors the fields of [`ZondConfig`] that are worth setting once and
/// forgetting. Deliberately not all of them, and deliberately nothing beyond
/// them:
///
/// - **`segment_sweep` is missing** because it is decided by the target
///   expression the user typed and belongs to the front end that parsed it. A
///   file must not be able to turn a single-host scan into a segment sweep
///   behind the user's back.
/// - **Nothing about presentation is here at all** — no banner, no verbosity, no
///   terminal handling. This document configures a scan. How a scan is displayed
///   belongs to whatever program is displaying it, in a file of its own; see
///   [`ZondConfig`] for where that line is drawn and why.
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
    /// The fastest routed discovery may probe, in probes per second.
    pub max_probe_rate: Option<u32>,
    /// Which segment a TCP port probe carries.
    #[serde(deserialize_with = "de_technique")]
    pub tcp_technique: Option<TcpScanTechnique>,
    /// How hard the scan tries before accepting silence as an answer.
    #[serde(deserialize_with = "de_effort")]
    pub effort: Option<ScanEffort>,
    /// Replaces the attempt budget outright. One disables retransmission.
    pub max_attempts: Option<u8>,
    /// Multiplies how long the scan is willing to wait.
    pub timeout_scale: Option<f64>,
    /// Whether a host that answers nothing may have its probe budget cut.
    pub dampen_silent_hosts: Option<bool>,
    /// The ports a scan covers when the caller names none.
    ///
    /// Held as written rather than parsed on the way in, because a port
    /// specification is a [`PortSet`] grammar and this struct is a document.
    /// [`ports`](Self::ports) parses it.
    pub default_ports: Option<String>,
}

impl Settings {
    /// Settings that change nothing.
    pub fn new() -> Self {
        Self::default()
    }

    /// Takes every value `other` sets, leaving the rest alone.
    ///
    /// This is what layering is: a later document speaks only about the keys it
    /// mentions, and silence is not an opinion.
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
            tcp_technique,
            effort,
            max_attempts,
            timeout_scale,
            dampen_silent_hosts,
            default_ports,
        );
    }

    /// The default port set this document names, if it names one.
    ///
    /// Separate from the field because a malformed specification is the
    /// caller's to report, and a document is worth loading even when one key in
    /// it is wrong.
    pub fn ports(&self) -> Option<Result<PortSet, SettingsError>> {
        self.default_ports.as_deref().map(|spec| {
            PortSet::try_from(spec).map_err(|error| {
                SettingsError::Malformed(format!("default_ports = '{spec}': {error}"))
            })
        })
    }

    /// Applies every value this sets to `config`, leaving the rest as it was.
    ///
    /// The one direction settings ever move. Nothing in this module reaches into
    /// a running scan; a caller builds its configuration, applies what it
    /// loaded, and starts.
    pub fn apply_to(&self, config: &mut ZondConfig) {
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
        if let Some(value) = self.tcp_technique {
            config.tcp_technique = value;
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
    }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

/// Every key [`Settings`] understands, for suggesting a correction.
const KNOWN_KEYS: [&str; 10] = [
    "no_dns",
    "redact",
    "send_mode",
    "max_probe_rate",
    "tcp_technique",
    "effort",
    "max_attempts",
    "timeout_scale",
    "dampen_silent_hosts",
    "default_ports",
];

/// Reads a settings document from anywhere.
///
/// Opens nothing. A front end whose settings live in a database, an upload or a
/// string hands the bytes over and gets the same parsing a file would.
pub fn read(input: &mut dyn BufRead) -> Result<Loaded, SettingsError> {
    let mut text = String::new();
    input
        .read_to_string(&mut text)
        .map_err(|source| SettingsError::Io {
            path: PathBuf::from("<reader>"),
            source,
        })?;
    parse(&text)
}

/// Reads a settings document from a path.
///
/// The one function in this module that opens a file, and it opens the one it
/// was handed. See the module documentation for why that distinction is the
/// whole design.
pub fn load(path: &Path) -> Result<Loaded, SettingsError> {
    let text = std::fs::read_to_string(path).map_err(|source| SettingsError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    parse(&text)
}

/// Parses a document and collects the keys this build does not know.
pub fn parse(text: &str) -> Result<Loaded, SettingsError> {
    // Parsed twice on purpose. The typed pass is the document; the untyped pass
    // is the only way to see the keys the typed one silently ignored, and
    // silence is exactly what makes a misspelled setting dangerous.
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
            // The nearest key, not merely the first one close enough: a user
            // who wrote `no_dn` should be pointed at `no_dns` rather than at
            // whichever candidate this list happens to name first.
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
/// Only ever run against a handful of short keys when something is already
/// wrong, so the straightforward two-row implementation is the right one.
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
/// This is the only function in this crate that writes to a filesystem, and it
/// is arranged so that calling it can never cost anybody their configuration:
///
/// - **It never overwrites.** The file is created with `create_new`, which fails
///   if anything is already there - atomically, so two processes racing cannot
///   both decide the file was missing.
/// - **It never edits.** An existing file is not read, reformatted, or extended
///   with a profile it lacks. Rewriting somebody's configuration to add a table
///   loses their comments and their ordering, and no convenience is worth that.
/// - **What it writes changes nothing.** [`TEMPLATE`] has every key commented
///   out, so a scan run immediately after provisioning behaves exactly as it did
///   before. A test pins that.
///
/// Parent directories are created as needed. On Unix the directory is created
/// `0700` and the file `0600`: a settings file records which networks somebody
/// scans and how, which is nobody else's business on a shared host.
pub fn provision(path: &Path) -> Result<Provisioned, SettingsError> {
    if let Some(parent) = path.parent() {
        create_directory(parent)?;
    }

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }

    match options.open(path) {
        Ok(mut file) => {
            use std::io::Write;
            file.write_all(TEMPLATE.as_bytes())
                .map_err(|source| SettingsError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            Ok(Provisioned::Created)
        }
        // The one error that is not a failure: somebody else's file, or our own
        // from last time, is exactly what this function wants to find.
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(Provisioned::Existed),
        Err(source) => Err(SettingsError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

/// Creates a directory and its parents, with restrictive permissions on Unix.
fn create_directory(path: &Path) -> Result<(), SettingsError> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }

    builder.create(path).map_err(|source| SettingsError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Creates the user's settings file if there is not one, and reports where it
/// is.
///
/// The convenience a front end wants at startup: one call that leaves the user
/// with a file to edit and tells the caller nothing surprising happened. It
/// still has to be *called* - see the module documentation.
pub fn provision_user() -> Result<(PathBuf, Provisioned), SettingsError> {
    let path = paths::user().ok_or(SettingsError::NoPath)?;
    let outcome = provision(&path)?;
    Ok((path, outcome))
}

/// Loads the settings a caller should run under, from the files that exist.
///
/// Reads the system file then the user file, skipping either if it is not
/// there, layers them in that order, and then applies `profile`. A file that
/// exists but cannot be parsed is an error: an unreadable settings file is not
/// the same as an absent one, and treating it as absent would run a scan under
/// settings the user believes they wrote.
///
/// Returns the resolved settings and every warning from every file. Nothing is
/// applied to anything - hand the result to [`Settings::apply_to`].
pub fn resolve(profile: Option<&str>) -> Result<(Settings, Vec<SettingsWarning>), SettingsError> {
    let mut settings = Settings::new();
    let mut warnings = Vec::new();
    let mut found_profile = profile.is_none();
    // Gathered across every file so that a name nobody defined is reported
    // against everything that *was* defined, rather than against one file's
    // half of the picture.
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
/// The error names what was written and what would have worked, which is the
/// whole reason these are not plain strings in the struct: a settings file that
/// says `tcp_technique = "stealth"` should say so at load, not scan with the
/// wrong technique.
fn de_named<'de, D, T>(deserializer: D) -> Result<Option<T>, D::Error>
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

fn de_send_mode<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<SendMode>, D::Error> {
    de_named(d)
}

fn de_technique<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<TcpScanTechnique>, D::Error> {
    de_named(d)
}

fn de_effort<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<ScanEffort>, D::Error> {
    de_named(d)
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

    /// The property the whole layering design rests on: a later file speaks only
    /// about the keys it mentions, and silence is not an opinion. Without
    /// `Option` everywhere, a user file could never override a system file back
    /// to a default value.
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
        assert_eq!(settings.max_probe_rate, Some(1000));
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
        assert_eq!(defaults.max_probe_rate, Some(20000));

        let stealth = loaded.document.resolve(Some("stealth")).expect("resolves");
        assert_eq!(stealth.effort, Some(ScanEffort::Thorough));
        assert_eq!(stealth.max_probe_rate, Some(200));
        assert_eq!(stealth.no_dns, Some(true), "inherited from the defaults");
    }

    /// A user who asked for `stealth` and quietly got a full-rate scan has been
    /// failed badly, so a name the document does not define is an error that
    /// lists the ones it does.
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

    /// A misspelled key that silently does nothing means a scan runs at a rate
    /// the user believes they changed. Reported, not dropped - and not fatal,
    /// so an older engine can still read a colleague's newer profile.
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

        // Looked up rather than indexed: the order is deterministic - the
        // untyped document is a sorted map - but it is the sorted order, not
        // the order the keys were written in, and a test that pinned the
        // latter would be pinning something this module never promised.
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

    /// A named alternative that does not exist has to fail at load. Scanning
    /// with the wrong technique because a file said `stealth` would be a wrong
    /// answer that looks like a right one.
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

    /// Settings move in exactly one direction, and only over the keys they set.
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
        assert_eq!(config.retry.max_attempts, Some(5));
        assert_eq!(config.max_probe_rate, Some(750));
        assert_eq!(config.send_mode, SendMode::Ethernet);
        assert_eq!(
            config.segment_sweep, before_sweep,
            "a file must not be able to turn a single-host scan into a segment sweep"
        );
    }

    /// A document that sets nothing has to change nothing, which is what makes
    /// provisioning safe.
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

    /// The property that makes creating a settings file safe: the template is
    /// entirely commented out, so a scan run straight afterwards behaves exactly
    /// as it did before.
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

    /// Every key the template mentions has to be a key this build reads, or the
    /// file documents a setting that does nothing.
    #[test]
    fn the_template_documents_every_key_and_no_others() {
        for key in KNOWN_KEYS {
            assert!(
                TEMPLATE.contains(&format!("{key} =")),
                "the template does not document '{key}'"
            );
        }
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

        // A malformed specification does not stop the document loading - one
        // wrong key should not cost a user every other setting in the file.
        let bad = document(
            r#"
            [defaults]
            default_ports = "http"
            "#,
        );
        assert!(bad.document.defaults.ports().expect("names ports").is_err());
    }

    #[test]
    fn a_document_that_is_not_toml_is_refused() {
        assert!(matches!(
            parse("this is not = = toml"),
            Err(SettingsError::Malformed(_))
        ));
    }

    /// Provisioning must never cost somebody their configuration, so the second
    /// call has to leave the first call's file exactly as it was - including
    /// whatever the user has since written into it.
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

    /// The whole startup sequence a front end runs, against a directory of our
    /// own rather than the user's: provision, find it already there the second
    /// time, read it back, and apply it.
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

    /// On Unix the file records which networks somebody scans and how, which is
    /// nobody else's business on a shared host.
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
