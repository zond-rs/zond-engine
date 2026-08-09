// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

// Application Layer
pub const DNS_HDR_LEN: usize = 12;
// Network Layer
pub const ICMP_V6_ECHO_REQ_LEN: usize = 8;
pub const IP_V4_HDR_LEN: usize = 20;
pub const IP_V6_HDR_LEN: usize = 40;
// Data Link Layer
pub const ARP_LEN: usize = 28;
pub const ETH_HDR_LEN: usize = 14;
pub const MIN_ETH_FRAME_NO_FCS: usize = 60;
