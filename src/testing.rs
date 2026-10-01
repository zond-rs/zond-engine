// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Fixtures the crate's tests share
//!
//! Fixtures used by more than one module's tests. They depend on nothing else in
//! the crate, so the integration tiers under `tests/` load the same files by path.

pub(crate) mod loopback;
// Unix only here, where the tests that need it run; the tiers load it by path.
#[cfg(unix)]
pub(crate) mod own_process;
