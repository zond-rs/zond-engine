// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Host-level detections
//!
//! A detection whose subject is a whole host rather than one port. It draws a
//! conclusion no single port can make on its own: Kerberos, LDAP, and SMB open
//! together are a domain controller, where each port alone is just a service.
//!
//! This is the declarative host tier. A detection is authored as data, a gate over
//! the aggregate a host presents (which ports are open, which services were named)
//! and a finding to draw when the gate fits. It reads only facts the scan already
//! holds, so it sends nothing and runs once the port scan has finished naming a
//! host's services. A richer host tier, one that reads a port's own findings or
//! computes a verdict, is a later addition; presence correlation is what the first
//! detections need.
//!
//! It is deliberately not [network roles](crate::model::host::NetworkRole). A role
//! is a conclusion proven in its own protocol, never from a port number, so a host
//! with 80 open is not a web server there. A host detection is the opposite reading:
//! a finding drawn precisely from which ports a host presents together.

// Re-exported so the build-shared `schema` can name the finding vocabulary as
// `super::authoring` in both the library, where it lives one level up in
// `detect`, and `build.rs`, where every shared file is a crate-root sibling.
pub(crate) use super::authoring;

pub(crate) mod db;
pub(crate) mod schema;
pub(crate) mod stage;
