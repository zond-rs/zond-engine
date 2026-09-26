// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Fixtures the crate's tests share
//!
//! What more than one module's tests stand up, kept in one place rather than
//! copied to each. A fixture here reads nothing of the crate's own, so the
//! integration tiers under `tests/` load the same file by path and their
//! services behave exactly as the unit tests' do.

pub(crate) mod loopback;
// Unix alone here, where the only tests that need it run; the tiers load it
// by path on every platform.
#[cfg(unix)]
pub(crate) mod own_process;
