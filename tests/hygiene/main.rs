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
//! the module graph matches the order `lib.rs` claims and has no cycle, that
//! every cited file is in the repository, that a doc comment landed on the item
//! it was written for and every item the standard covers has one, and that the
//! obligations a module states and its callers keep are written down where the
//! next caller will meet them.
//!
//! Those obligations are kept by four censuses. Every reader of an ICMP error
//! says how it ties one to a probe; every file opening a capture that admits
//! ICMP says where it checks the protocol before it parses a byte; every
//! writer into the host store says how it is held to the exclusions; and every
//! file naming a port's sender says how an excluded one stays out. Each
//! census also holds itself to account: an entry has to say something, every
//! probe kind has to be placed by whether its capture admits ICMP, and the way
//! the ICMP censuses find a file is tried against the spellings it has to see
//! through and the prose it has to ignore.
//!
//! These are lints wearing a test's clothes, and they run with the ordinary
//! suite because `cargo test` is where a contributor looks. They need no
//! privileges, no network, and no fixtures.

mod architecture;
mod attribution;
mod citations;
mod documentation;
mod exclusions;
