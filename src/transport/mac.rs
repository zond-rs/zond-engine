// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extensions for MAC address conversions between pnet and the core domain model.

use crate::model::mac::MacAddr as CoreMacAddr;
use pnet_base::MacAddr as PnetMacAddr;

/// An extension trait to seamlessly convert from `pnet_base::MacAddr` to the
/// native `crate::model::mac::MacAddr`.
pub trait IntoCoreMac {
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
/// Needed because the two vocabularies meet in both directions now. An address
/// read off an interface arrives as the model's, and every frame this crate
/// emits is built by `pnet::packet`, which wants its own. Written as a trait
/// rather than a `From` impl for the same reason [`IntoCoreMac`] is one: neither
/// type is this crate's to add inherent conversions to.
pub trait IntoPnetMac {
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
