// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The domain vocabulary
//!
//! What a scan talks about: a [`Host`](host::Host), a [`Port`](port::Port), the
//! addresses to visit ([`IpSet`](ip::set::IpSet), [`TargetMap`](target::TargetMap)),
//! and the measurements a probe produces on the way ([`RttWindow`](rtt_window::RttWindow),
//! [`CaptureCounts`](capture::CaptureCounts)).
//!
//! **This module depends on nothing else in the crate, and that is a property to
//! keep rather than an accident of how it grew.** Every other module names these
//! types — the scanners fill them in, the report records them, the exporters
//! write them out, the parsers construct them — so anything this layer reached
//! back up to would be pulled into the foundation with it, and the layering
//! below it would stop meaning anything. A type belongs here when more than one
//! module has to agree on it; a type that only one module uses belongs in that
//! module.
//!
//! For the same reason nothing here is serializable. The wire format is a
//! separate contract, written out by hand in
//! [`export::schema`](crate::export::schema), so that moving a field in this
//! module is a private matter rather than a breaking change to somebody's
//! parser.
//!
//! [`parse`] is the other direction: the grammars that turn what a person wrote
//! — `192.168.1.0/24`, `[fe80::1%en0]:22` — into the values above. It takes its
//! hostname and zone resolution as caller-supplied callbacks precisely so that
//! constructing a target does not drag the host's interface table into the leaf.

pub mod capture;
pub mod deadline;
pub mod fingerprint;
pub mod host;
pub mod ip;
pub mod mac;
pub mod parse;
pub mod port;
pub mod retry;
pub mod rtt_window;
pub mod target;
pub mod technique;
pub mod timer;
