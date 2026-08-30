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
//!
//! **The facade is the whole of it.** Every name below is re-exported here and
//! the modules holding them are private, so each has exactly one public path.
//! Naming both would commit the crate to two spellings of every item and to the
//! file layout underneath, and the layout is where this module still moves: how
//! a source address is chosen is an implementation detail that has changed twice
//! and will again, while `SourceResolver` is the answer either way.
mod lan;
mod link;
mod resolve;
mod routing;
mod source;
mod utils;

pub use lan::{LanLink, ViabilityError, lan_link, lan_network};
pub use link::{Link, LinkAddress, LinkKind, interfaces};
pub use resolve::{resolve_keyword, resolve_zone};
pub use routing::{
    MAX_ENUMERABLE_ADDRESSES, RoutedTarget, RoutedTargets, is_enumerable, map_ips_to_interfaces,
};
pub use source::SourceResolver;
pub use utils::{is_layer_2_capable, is_on_link, prioritized_interfaces};
