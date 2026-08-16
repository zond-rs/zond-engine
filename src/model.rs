// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The domain vocabulary
//!
//! The types a scan is described in: a [`Host`](host::Host), a
//! [`Port`](port::Port), the addresses to visit ([`IpSet`](ip::set::IpSet) and
//! [`TargetMap`](target::TargetMap)), and what the capture saw on the way
//! ([`CaptureCounts`](capture::CaptureCounts)).
//!
//! [`parse`] is the way in. It holds the grammars that turn written targets such
//! as `192.168.1.0/24` or `[fe80::1%en0]:22` into the values above.
//!
//! # Usable on its own
//!
//! This module depends on nothing else in the crate. You can parse targets, do
//! arithmetic on address sets, and hold hosts and ports without starting a scan
//! or linking anything that would.
//!
//! Two consequences are worth knowing about.
//!
//! Nothing here resolves anything for itself. Expanding a keyword like `lan`,
//! looking up an interface by name, and resolving a hostname all mean reading
//! the machine the process runs on, so each arrives as a function you supply.
//! An expression that needs a lookup you did not provide is refused rather than
//! guessed at.
//!
//! Nothing here writes output. These functions return values and never log,
//! because only the caller knows what it asked for and at what verbosity it
//! wants to hear about it.
//!
//! # Not the wire format
//!
//! None of these types are serializable. The document a scan produces is a
//! separate contract, written by hand in
//! [`export::schema`](crate::export::schema), so that a field moving here stays
//! a private matter instead of breaking somebody's parser.

pub mod capture;
pub mod host;
pub mod ip;
pub mod mac;
pub mod parse;
pub mod port;
pub mod target;
pub mod technique;
