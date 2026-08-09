// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! This module is currently a wrapper for the 'tracing' crate.
//! The goal is to provide an abstraction so that other modules
//! do not depend on tracing directrly, making it easy to swap
//! our way of logging more easily in the future if needed.

#[macro_export]
macro_rules! info {
    (incoming, $($arg:tt)+) => {
        tracing::info!(status = "incoming", $($arg)+)
    };
    (outgoing, $($arg:tt)+) => {
        tracing::info!(status = "outgoing", $($arg)+)
    };
    ($($arg:tt)+) => {
        tracing::info!(status = "info", $($arg)+)
    };
}

#[macro_export]
macro_rules! success {
    ($($arg:tt)+) => {
        tracing::info!(status = "success", $($arg)+)
    };
}

#[macro_export]
macro_rules! debug {
    ($($arg:tt)+) => {
        tracing::debug!(status = "debug", $($arg)+)
    };
}

#[macro_export]
macro_rules! error {
    ($($arg:tt)+) => {
        tracing::error!(status = "error", $($arg)+)
    };
}

#[macro_export]
macro_rules! warn {
    ($($arg:tt)+) => {
        tracing::warn!(status = "warn", $($arg)+)
    };
}
