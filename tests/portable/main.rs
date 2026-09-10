// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Tier 1: what runs anywhere
//!
//! Real servers on loopback and real files in a temporary directory. A listener
//! is bound, a connection is made, a banner comes back. Nothing is faked, which
//! is what makes these convincing and also what limits them: a cooperative
//! kernel produces only open and closed, so lost probes, firewalls and injected
//! latency belong to the `simulated` tier instead.
//!
//! `import` is the odd one, binding no socket at all, because the surface it
//! covers reads documents. It sits here because it needs nothing but a
//! temporary directory, which is the property this tier is defined by.
//!
//! No privileges and no network setup, so this tier runs identically on Linux
//! and macOS. When the process happens to be root, a scan takes its raw-socket
//! path rather than the connect fallback; the assertions that depend on the
//! fallback call `support::is_privileged` and skip rather than flake.

#[path = "../support/mod.rs"]
mod support;

mod detections;
mod discovery;
mod export;
mod fingerprint_embedding;
mod hostname_resolution;
mod import;
mod lifecycle;
mod liveness;
mod port_states;
mod reporting;
mod service_fingerprint;
mod targets;
mod wire_parsers;
