// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Checks on the repository, not on the engine
//!
//! Nothing here binds a socket or calls the library. Each module reads source
//! files off disk and holds the tree to a rule the compiler cannot express: that
//! the module graph matches the order `lib.rs` claims, that every cited file is
//! in the repository, that a doc comment landed on the item it was written for,
//! and that two obligations a module states and its callers keep are written
//! down where the next caller will meet them: every reader of an ICMP error says
//! how it ties one to a probe, and every writer into the host store says how it
//! is held to the exclusions.
//!
//! These are lints wearing a test's clothes, and they run with the ordinary
//! suite because `cargo test` is where a contributor looks. They need no
//! privileges, no network, and no fixtures.

mod architecture;
mod attribution;
mod citations;
mod documentation;
mod exclusions;
