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
//! `import` and `exclusions` are the odd ones, binding no socket at all:
//! `import` covers a surface that reads documents, and `exclusions` builds a
//! discovery plan from this host's interface table and opens nothing. They sit
//! here because they need nothing beyond a temporary directory, which is the
//! property this tier is defined by.
//!
//! No privileges and no network setup, so this tier runs identically on Linux
//! and macOS. Every target is loopback, whose only raw route is a raw socket,
//! so where the process can open one, as root or on Linux holding
//! `CAP_NET_RAW`, a scan takes it rather than the connect fallback. The
//! assertions that depend on the fallback call `support::is_privileged`, which
//! asks exactly that, and skip rather than flake.

#[path = "../support/mod.rs"]
mod support;

mod detections;
mod discovery;
mod exclusions;
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
