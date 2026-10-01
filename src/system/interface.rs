// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later
//! # The network hardware this machine has
//!
//! What the host is plugged into, and how a target is reached through it. Four
//! questions to answer before a packet can be built:
//!
//! - **What links are there**, and which could carry a probe at all.
//!   [`Link`] and [`interfaces`].
//! - **Which link is "the network"** a person means by `lan`. [`lan_link`].
//! - **How is a target reached**: on a segment this machine is attached to,
//!   behind a gateway, or by neither. [`map_ips_to_interfaces`].
//! - **What address does a probe leave from**, which for a raw socket the
//!   kernel will not compute. [`SourceResolver`].
//!
//! A bare IPv6 link-local matches every interface and is reported as
//! unanswerable, and an off-link range too large to walk is refused whole.
//!
//! Every public name is re-exported here and the modules holding them are
//! private, so each item has one public path and the file layout underneath can
//! change.
mod lan;
mod link;
mod resolve;
mod routing;
mod source;

pub use lan::{
    LanLink, ViabilityError, lan_link, lan_network, lan_viability, prioritized_interfaces,
};
// The seam `lan_link` reads the machine through, so a caller holding an
// interface table can ask `lan` of that table. See `resolve::for_listening_on`.
pub(crate) use lan::lan_link_with;
pub use link::{
    Addressing, Link, LinkAddress, LinkKind, interfaces, is_layer_2_capable, is_on_link,
};
// The raw table, for readers that need what a `Link` does not carry, such as a
// gateway's hardware address. See `host_table`.
pub(crate) use link::{host_table, interfaces_or_none};
pub use resolve::{resolve_keyword, resolve_zone};
pub use routing::{
    MAX_ENUMERABLE_ADDRESSES, RoutedTarget, RoutedTargets, is_enumerable, map_ips_to_interfaces,
};
// The forced-source override for a scan pinned to an interface. See
// `DiscoveryPlan::build`.
pub(crate) use routing::map_ips_to_interfaces_forced;
// Which targets a self-built frame cannot reach. Kept crate-private because it
// reflects a gap (the probe sender has no neighbour discovery) that a consumer
// should not build on.
pub(crate) use routing::{BeyondFrames, FrameSender, beyond_frames};
// Neighbours the routing table refuses, held back from the segment sweep.
pub(crate) use routing::refused_neighbours;
#[cfg(all(test, unix))]
pub(crate) use source::RouteAnswer;
pub use source::SourceResolver;
pub(crate) use source::{NoSource, OnLinkTable, probe_route_source, refuses_neighbour};
