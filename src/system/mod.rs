// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.
//! # Host System
//!
//! This module brokers the host-facing capabilities a scan depends on.
//! [`interface`] resolves, validates, and routes the network hardware attached to
//! the host, classifying local connections (wired vs wireless), fetching network
//! IPv4 assignments, and routing an arbitrary set of targets securely out of the
//! host boundaries. [`privilege`] reports whether the process may open raw
//! sockets.
//!
//! Exposes a clean facade for all host system logic to consumers.

pub mod interface;
pub mod privilege;
