// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Between the model's hardware address and `pnet`'s
//!
//! Every frame this crate builds or reads goes through `pnet::packet`, which
//! has a `MacAddr` of its own. Nothing public names that type: the builders
//! and readers take and return [`MacAddr`](crate::model::mac::MacAddr), and
//! convert here, at the call into the packet library.

use crate::model::mac::MacAddr as CoreMacAddr;
use pnet_base::MacAddr as PnetMacAddr;

/// From `pnet`'s address to the model's, for one read off a frame.
pub(crate) trait IntoCoreMac {
    /// The same address in the model's own type, for a MAC read off a frame or
    /// an interface on its way into a host record.
    fn into_core(self) -> CoreMacAddr;
}

impl IntoCoreMac for PnetMacAddr {
    #[inline]
    fn into_core(self) -> CoreMacAddr {
        CoreMacAddr::new(self.0, self.1, self.2, self.3, self.4, self.5)
    }
}

/// The reverse: a model address as the packet builders want one.
///
/// Needed because the two vocabularies meet in both directions. An address
/// read off an interface arrives as the model's, and every frame this crate
/// emits is built by `pnet::packet`, which wants its own. Written as a trait
/// rather than a `From` impl, as [`IntoCoreMac`] is, because an impl of a
/// public trait is public wherever it sits, and a `From` between the two
/// addresses would put the packet library's back in the public API.
pub(crate) trait IntoPnetMac {
    /// The same address in the type `pnet`'s packet builders take, for handing
    /// a model address to whatever is writing the frame.
    fn into_pnet(self) -> PnetMacAddr;
}

impl IntoPnetMac for CoreMacAddr {
    #[inline]
    fn into_pnet(self) -> PnetMacAddr {
        let [a, b, c, d, e, f] = self.octets();
        PnetMacAddr::new(a, b, c, d, e, f)
    }
}
