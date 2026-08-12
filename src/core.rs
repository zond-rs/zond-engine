// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod config;
pub mod handle;
pub mod models;
// Nothing here is public: it is the five macros the engine emits its own
// diagnostics through, and a library that exported those would shadow
// `tracing`'s and `log`'s macros of the same names in any consumer that
// glob-imported it. See the module for the rest of the argument.
pub(crate) mod logging;
pub mod parse;
pub mod redact;
pub mod report;
pub mod session;
