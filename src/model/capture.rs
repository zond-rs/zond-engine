// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a capture saw, and what it did with it.
//!
//! Two things, in the vocabulary rather than beside the capture backend that
//! fills them in, because in both cases more than one module has to agree on
//! the shape. [`CaptureCounts`] is written by the capture and read by the
//! report. [`IpObservation`] is written by the capture and read by whatever
//! wants to know what a stack put in its headers.
//!
//! Putting them here lets the record describe its own shape instead of
//! borrowing it from the transport it happened to come from, and keeps a
//! backend with no kernel buffer at all — a synthetic receive stream in a test
//! — able to say so.

/// What a reply's IP header said, past the addressing the scanner needed to
/// correlate it.
///
/// A packet's headers carry two quite different kinds of information. The
/// addresses and the protocol are *routing*: they say who sent this and how to
/// read the rest, and the scanners have always kept them. Everything else — how
/// many hops are left, whether the datagram may be fragmented, what identifier
/// was stamped on it — is a fact about the *stack that emitted it*, chosen by
/// its authors and nearly identical across every packet that stack will ever
/// send. That second kind is what this carries, and it is why a reply to an
/// ordinary port probe is enough to say something about the machine behind it.
///
/// # Split by family rather than flattened
///
/// IPv4 and IPv6 do not describe the same header, and pretending otherwise is
/// the failure mode worth designing out. Half these fields exist in one family
/// and not the other: there is no identification field in an IPv6 header, and no
/// don't-fragment bit, because an IPv6 datagram is never fragmented in transit.
/// Modelled as one flat struct, those become an `Option` that is always `None`
/// for one family and a `bool` that is silently `false` for it — and a rule
/// written against `dont_fragment == false` would then match every IPv6 packet
/// ever captured while looking perfectly correct. An enum makes the question
/// unaskable in the family where it has no answer.
///
/// [`remaining_hops`](Self::remaining_hops) is the one field both families do
/// have, under two different names, so it is the one thing worth reading without
/// first asking which family this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IpObservation {
    /// What an IPv4 header said.
    V4(Ipv4Observation),
    /// What an IPv6 header said.
    V6(Ipv6Observation),
}

impl IpObservation {
    /// The hop counter as it arrived: an IPv4 TTL or an IPv6 hop limit.
    ///
    /// **This is not the value the sender wrote.** Every router on the path
    /// decrements it, so what arrives is the initial value minus the hop count,
    /// and the initial value is the part that identifies a stack. Recovering it
    /// means knowing how far away the host is; rounding up to the nearest
    /// familiar starting value is a guess that holds until a path is long, and
    /// then fails silently.
    pub fn remaining_hops(self) -> u8 {
        match self {
            IpObservation::V4(observed) => observed.ttl,
            IpObservation::V6(observed) => observed.hop_limit,
        }
    }

    /// Whether the reply arrived as a fragment rather than a whole datagram.
    ///
    /// Worth asking before reading anything else here. A fragment's header
    /// describes the fragment, and the fields that identify a stack — the
    /// window and options of the segment behind it especially — either belong to
    /// a different piece of the datagram or are absent entirely. A fragmented
    /// reply is evidence about the path, not about the sender.
    pub fn is_fragment(self) -> bool {
        match self {
            // True for the first fragment and no other, which is every fragment
            // that gets this far. `parse_ip_segment` refuses a datagram whose
            // fragment offset is non-zero, on both families and for the same
            // reason: what follows the header of a later fragment is the middle
            // of somebody's payload rather than a Layer-4 header.
            //
            // Without that refusal this answered the More Fragments bit, which
            // the *last* fragment of a fragmented datagram does not set, so the
            // one reply whose segment fields belong to a different piece of the
            // datagram was the one reply this reported as whole.
            IpObservation::V4(observed) => observed.more_fragments,
            // An IPv6 sender's fragments carry a fragment extension header, and
            // `walk_ipv6_headers` stops at any whose offset is non-zero, so the
            // first fragment is the only one that arrives and it is not
            // distinguishable here from a whole datagram. A caller that needs to
            // know reads the extension header, which this does not carry.
            IpObservation::V6(_) => false,
        }
    }
}

/// The fields of an IPv4 header that describe the stack that wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv4Observation {
    /// The time-to-live as it arrived, already decremented once per hop
    /// crossed. See [`IpObservation::remaining_hops`].
    pub ttl: u8,

    /// The fragment identifier.
    ///
    /// Interesting for how it *changes* across several replies rather than for
    /// any single value: zero throughout, counting up globally, counting up per
    /// connection and random are four different policies, and which one a stack
    /// follows is close to a signature. One observation cannot tell them apart,
    /// which is why this is recorded per reply and read across them.
    pub identification: u16,

    /// Whether the sender forbade fragmentation in transit.
    pub dont_fragment: bool,

    /// Whether more fragments of this datagram follow.
    /// See [`IpObservation::is_fragment`].
    pub more_fragments: bool,

    /// Differentiated services, six bits. Almost always zero from a host, and
    /// interesting exactly when it is not.
    pub dscp: u8,

    /// Explicit congestion notification, two bits. What a stack echoes here is
    /// set by whether it negotiated ECN at all, which stacks disagree about.
    pub ecn: u8,
}

/// The fields of an IPv6 header that describe the stack that wrote it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ipv6Observation {
    /// The hop limit as it arrived, already decremented once per hop crossed.
    /// See [`IpObservation::remaining_hops`].
    pub hop_limit: u8,

    /// Traffic class, eight bits: the IPv6 spelling of IPv4's DSCP and ECN
    /// together.
    pub traffic_class: u8,

    /// The flow label, twenty bits.
    ///
    /// Whether a stack sets one *at all* is the signal. The specification allows
    /// zero, several stacks always send zero, and others derive a value per
    /// flow — so the distinction worth recording is not which label was chosen
    /// but whether choosing one was attempted.
    pub flow_label: u32,
}

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

    /// Saturating, like every other count in the model.
    ///
    /// These come from a kernel and are summed across however many captures a
    /// scan opened. A total too large to represent is still enormous, where a
    /// wrapped one reads as a quiet capture and would be believed.
    fn add(self, other: Self) -> Self {
        Self {
            received: self.received.saturating_add(other.received),
            dropped: self.dropped.saturating_add(other.dropped),
            if_dropped: self.if_dropped.saturating_add(other.if_dropped),
        }
    }
}

impl std::ops::AddAssign for CaptureCounts {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl std::iter::Sum for CaptureCounts {
    /// Totals a scan's captures. Empty sums to all zeros, which is what a scan
    /// that opened no capture observed.
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.fold(Self::default(), |total, counts| total + counts)
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counts_add_field_by_field() {
        let total: CaptureCounts = [
            CaptureCounts {
                received: 10,
                dropped: 1,
                if_dropped: 0,
            },
            CaptureCounts {
                received: 5,
                dropped: 0,
                if_dropped: 2,
            },
        ]
        .into_iter()
        .sum();

        assert_eq!(total.received, 15);
        assert_eq!(total.dropped, 1);
        assert_eq!(total.if_dropped, 2);
    }

    /// A wrapped total reads as a quiet capture, which is the one conclusion
    /// these counts exist to prevent anybody reaching.
    #[test]
    fn a_total_too_large_to_represent_saturates_rather_than_wrapping() {
        let huge = CaptureCounts {
            received: u64::MAX,
            dropped: u64::MAX,
            if_dropped: u64::MAX,
        };
        let one = CaptureCounts {
            received: 1,
            dropped: 1,
            if_dropped: 1,
        };

        let total = huge + one;

        assert_eq!(total.received, u64::MAX);
        assert_eq!(total.dropped, u64::MAX);
        assert_eq!(total.if_dropped, u64::MAX);
    }

    #[test]
    fn an_empty_sum_is_all_zeros() {
        let total: CaptureCounts = std::iter::empty().sum();
        assert_eq!(total, CaptureCounts::default());
    }
}
