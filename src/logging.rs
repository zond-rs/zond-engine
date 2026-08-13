// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Internal diagnostics
//!
//! How the engine's own code emits diagnostic events. Every macro here is
//! `pub(crate)`, and that is the whole of its API design.
//!
//! **A library must not export these.** Exported from the crate root they would
//! be `zond_engine::info!` and `zond_engine::error!` — five of the most generic
//! identifiers in Rust, shadowing `tracing`'s and `log`'s macros of the same
//! names in any consumer that glob-imports this crate, and pinned by semver
//! forever. Worse, a macro expanding to `tracing::info!` resolves that path in
//! the *caller's* namespace: a consumer who does not happen to depend on
//! `tracing` themselves gets a compile error out of a macro they were invited to
//! use. Neither problem is reachable from inside this repository, which is why
//! the expansions here are absolute (`::tracing::`) and the macros are not
//! exported.
//!
//! What a consumer sees instead is the events. The engine emits `tracing` and
//! installs no subscriber, so whoever embeds it decides whether anything is
//! rendered and how.
//!
//! Two fields carry the conventions a front end reads. `status` names what kind
//! of thing an event is, which is what a terminal colours on and a structured
//! consumer filters on. `verbosity` is set by the caller on anything below a
//! headline — a default run shows none of it.

macro_rules! info {
    (incoming, $($arg:tt)+) => {
        ::tracing::info!(status = "incoming", $($arg)+)
    };
    (outgoing, $($arg:tt)+) => {
        ::tracing::info!(status = "outgoing", $($arg)+)
    };
    ($($arg:tt)+) => {
        ::tracing::info!(status = "info", $($arg)+)
    };
}

macro_rules! success {
    ($($arg:tt)+) => {
        ::tracing::info!(status = "success", $($arg)+)
    };
}

macro_rules! error {
    ($($arg:tt)+) => {
        ::tracing::error!(status = "error", $($arg)+)
    };
}

// Defined under a name nothing else claims, then re-exported as `warn` below.
// `warn` is a built-in attribute, so re-exporting a macro of that name by its
// own name is ambiguous and will not compile; renaming on the way out resolves
// an unambiguous path and still binds the name every call site writes.
macro_rules! warn_macro {
    ($($arg:tt)+) => {
        ::tracing::warn!(status = "warn", $($arg)+)
    };
}

pub(crate) use error;
pub(crate) use info;
pub(crate) use success;
pub(crate) use warn_macro as warn;
