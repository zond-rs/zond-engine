// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Host-level detections
//!
//! A detection whose subject is a whole host: Kerberos, LDAP and SMB open
//! together are a domain controller, where each port alone is just a service.
//!
//! A host detection is data: a gate over which ports are open and which
//! services were named, and the findings to draw when it fits. It reads only
//! what the scan holds, sends nothing, and runs after the port scan.
//!
//! It is [`Derived`](super::manifest::Class::Derived) and reaches a finding as
//! [`Passive`](crate::model::finding::DetectionClass::Passive), within every
//! [envelope](crate::config::DetectionEnvelope), so this tier takes no envelope.
//!
//! Unlike [network roles](crate::model::host::NetworkRole), which are proven in
//! their own protocol, a host detection reasons from the ports a host presents.

// So the build-shared `schema` can name `super::authoring` in both the library
// and `build.rs`.
pub(crate) use super::authoring;
pub(crate) use super::manifest;

pub(crate) mod db;
pub(crate) mod schema;
pub(crate) mod stage;
