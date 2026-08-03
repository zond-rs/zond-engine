// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Scan tuning
//!
//! The timeouts and concurrency ceilings the unprivileged (TCP connect) scan
//! paths run against, gathered in one place. These used to be declared per module:
//! a `1000ms` connect budget spelled once in [`connect`](super::connect) and again
//! in [`service`](super::service), and a fan-out of `50` living as both a
//! [`scan`](super::scan) constant and a `service` constant. Tuning one copy then
//! quietly left the other behind. Defining them here once keeps the knobs
//! consistent and easy to find.
//!
//! Only the connect-based paths are covered. The raw-socket scanners size
//! themselves adaptively from observed round-trip times (see
//! [`AdaptiveDeadline`](crate::core::models::deadline::AdaptiveDeadline)) rather
//! than from fixed constants, so they have no knobs to gather here.

use std::time::Duration;

/// How long a single TCP connect probe waits before treating silence as a drop.
/// Shared by the connect port and host scanners and by the service-detection
/// connect, which all open the same kind of connection for the same purpose.
pub(in crate::scanner) const CONNECT_PROBE_TIMEOUT: Duration = Duration::from_millis(1000);

/// How many TCP connects the port-scan and service-detection fan-outs keep in
/// flight at once. Bounded so a wide scan stays fast without exhausting OS
/// sockets.
pub(in crate::scanner) const CONNECT_CONCURRENCY: usize = 50;

/// How many connect probes the unprivileged discovery sweep keeps in flight.
/// Far higher than [`CONNECT_CONCURRENCY`] because each probe is a bare liveness
/// check against a handful of ports, not a full fingerprint conversation.
pub(in crate::scanner) const DISCOVERY_CONCURRENCY: usize = 2048;
