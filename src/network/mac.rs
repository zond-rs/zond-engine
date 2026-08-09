// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! Extensions for MAC address conversions between pnet and the core domain model.

use crate::core::models::mac::MacAddr as CoreMacAddr;
use pnet::util::MacAddr as PnetMacAddr;

/// An extension trait to seamlessly convert from `pnet::util::MacAddr` to the
/// native `crate::core::models::mac::MacAddr`.
pub trait IntoCoreMac {
    fn into_core(self) -> CoreMacAddr;
}

impl IntoCoreMac for PnetMacAddr {
    #[inline]
    fn into_core(self) -> CoreMacAddr {
        CoreMacAddr::new(self.0, self.1, self.2, self.3, self.4, self.5)
    }
}
