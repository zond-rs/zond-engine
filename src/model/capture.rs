// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What the kernel capture did with the frames it admitted.
//!
//! One struct, in the vocabulary rather than beside the capture backend that
//! fills it in, because two modules have to agree on it: the capture counts the
//! frames, and the report carries the counts to whoever reads the scan. Putting
//! it here lets the record describe its own shape instead of borrowing it from
//! the transport it happened to come from, and keeps a backend with no kernel
//! buffer at all, such as a synthetic receive stream in a test, able to say
//! so.

/// What the kernel did with the frames its BPF filter admitted, cumulative over
/// a capture's lifetime.
///
/// `dropped` is the field this exists for. It counts frames that matched the
/// filter, reached the kernel's buffer, and were discarded because this process
/// did not read them in time. A scanner cannot tell such a frame from one that
/// was never sent - both are silence - so a reply lost here is
/// indistinguishable from a host that did not answer, and no amount of
/// retransmission helps if the retry's reply is lost the same way. That makes it
/// the one loss the scanner has to be told about rather than left to infer.
///
/// Read against a scanner's own counters with care. The filters that produce
/// these are narrow but not private: the SYN filter admits every TCP SYN and RST
/// crossing any captured interface, so `received` includes traffic that has
/// nothing to do with the scan. It bounds the receive path's load, not the
/// scan's share of it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CaptureCounts {
    /// Frames the capture accepted and handed to this process.
    pub received: u64,
    /// Frames discarded because the buffer was full when they arrived.
    pub dropped: u64,
    /// Frames discarded by the interface or its driver before the capture saw
    /// them. Not every platform reports this, so a zero is weaker evidence here
    /// than in [`dropped`](Self::dropped).
    pub if_dropped: u64,
}

impl std::ops::Add for CaptureCounts {
    type Output = Self;

    fn add(self, other: Self) -> Self {
        Self {
            received: self.received + other.received,
            dropped: self.dropped + other.dropped,
            if_dropped: self.if_dropped + other.if_dropped,
        }
    }
}
