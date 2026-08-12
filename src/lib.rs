// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

pub mod core;
pub mod export;
pub mod fingerprinting;
pub mod host_sys;
pub mod import;
pub mod network;
pub mod protocols;
pub mod scanner;
pub mod system;

// The engine's own diagnostic macros, reachable as `crate::info!` and friends
// from anywhere in the crate. They are deliberately not part of the public API;
// see `core::logging` for what exporting them would cost a consumer.
pub(crate) use crate::core::logging::{error, info, success, warn};
