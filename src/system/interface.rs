// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//! # Network Interfaces
//!
//! This module resolves, validates, and routes the network hardware interfaces attached
//! to the host. It provides capabilities like classifying local hardware
//! connections (wired vs wireless), fetching network IPv4 assignments,
//! and routing an arbitrary set of network targets securely out of the host boundaries.
//!
//! Exposes a clean facade for all interface management logic to consumers.
pub mod ext;
pub mod lan;
pub mod os;
pub mod resolve;
pub mod routing;
pub mod source;
pub mod utils;

pub use ext::NetworkInterfaceExtension;
pub use lan::{ViabilityError, get_lan_network};
pub use routing::{RoutedTarget, RoutedTargets, map_ips_to_interfaces};
pub use source::SourceResolver;
pub use utils::{get_prioritized_interfaces, is_layer_2_capable, is_on_link};
