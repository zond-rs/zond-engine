// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Between the model's hardware address and `pnet`'s
//!
//! `pnet::packet` has its own `MacAddr`. Public builders and readers take and
//! return [`MacAddr`](crate::model::mac::MacAddr) and convert here, at the call
//! into the packet library.

use crate::model::mac::MacAddr as CoreMacAddr;
use pnet_base::MacAddr as PnetMacAddr;

/// From `pnet`'s address to the model's.
pub(crate) trait IntoCoreMac {
    /// The same address in the model's type.
    fn into_core(self) -> CoreMacAddr;
}

impl IntoCoreMac for PnetMacAddr {
    #[inline]
    fn into_core(self) -> CoreMacAddr {
        CoreMacAddr::new(self.0, self.1, self.2, self.3, self.4, self.5)
    }
}

/// From the model's address to the one `pnet`'s packet builders take.
///
/// A crate-private trait, like [`IntoCoreMac`], because a `From` impl between
/// the two would be public and put `pnet`'s type in the public API.
pub(crate) trait IntoPnetMac {
    /// The same address in `pnet`'s type.
    fn into_pnet(self) -> PnetMacAddr;
}

impl IntoPnetMac for CoreMacAddr {
    #[inline]
    fn into_pnet(self) -> PnetMacAddr {
        let [a, b, c, d, e, f] = self.octets();
        PnetMacAddr::new(a, b, c, d, e, f)
    }
}
