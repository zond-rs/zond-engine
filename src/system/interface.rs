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
//! questions, and every one of them has to be answered before a packet can be
//! built:
//!
//! - **What links are there**, and which could carry a probe at all.
//!   [`Link`] and [`interfaces`].
//! - **Which link is "the network"** a person means by `lan`. [`lan_link`].
//! - **How is a target reached**: on a segment this machine is attached to,
//!   behind a gateway, or by neither. [`map_ips_to_interfaces`].
//! - **What address does a probe leave from**, which for a raw socket the
//!   kernel will not compute. [`SourceResolver`].
//!
//! The last two are where the module's judgement lives, and both refuse more
//! carefully than they answer: a bare IPv6 link-local matches every interface
//! and is reported as the unanswerable question it is, and an off-link range too
//! large to walk is refused rather than half-scanned.
//!
//! The facade is the whole of it. Every name below is re-exported here and
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

pub use lan::{
    LanLink, ViabilityError, lan_link, lan_network, lan_viability, prioritized_interfaces,
};
// Not published: the seam `lan_link` reads the machine through, so a caller that
// already holds an interface table can ask `lan` of that table instead. See
// `resolve::for_listening_on`.
pub(crate) use lan::lan_link_with;
pub use link::{
    Addressing, Link, LinkAddress, LinkKind, interfaces, is_layer_2_capable, is_on_link,
};
pub use resolve::{resolve_keyword, resolve_zone};
pub use routing::{
    MAX_ENUMERABLE_ADDRESSES, RoutedTarget, RoutedTargets, is_enumerable, map_ips_to_interfaces,
};
pub use source::SourceResolver;
