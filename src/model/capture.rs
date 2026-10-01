// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! What a capture saw, and what it did with it.
//!
//! [`CaptureCounts`] is written by the capture and read by the report. [`IpObservation`]
//! is written by the capture and read by whatever wants to know what a stack put in its
//! headers. Both live in the vocabulary because several modules share their shape, and
//! a backend with no kernel buffer, such as a synthetic receive stream in a test, can
//! still fill them in.

/// What a reply's IP header said, past the addressing the scanner needed to
/// correlate it.
///
/// Beyond the addresses and protocol, a header records how many hops are left, whether
/// the datagram may be fragmented, and what identifier was stamped on it. Those are
/// choices of the stack that sent it, nearly identical across every packet it sends,
/// which is why a reply to an ordinary port probe says something about the machine
/// behind it.
///
/// # Split by family
///
/// Half these fields exist in only one family: an IPv6 header has no identification
/// field and no don't-fragment bit, since IPv6 datagrams are never fragmented in
/// transit. In one flat struct, a rule written against `dont_fragment == false` would
/// silently match every IPv6 packet. The enum makes such a question unaskable where it
/// has no answer.
///
/// [`remaining_hops`](Self::remaining_hops) is the one field both families have, under
/// different names.
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
    /// Every router on the path decrements it, so this is the initial value minus the
    /// hop count. The initial value is what identifies a stack; recovering it means
    /// knowing the host's distance. Rounding up to the nearest familiar starting value
    /// fails silently on long paths.
    pub fn remaining_hops(self) -> u8 {
        match self {
            IpObservation::V4(observed) => observed.ttl,
            IpObservation::V6(observed) => observed.hop_limit,
        }
    }

    /// Whether the reply arrived as a fragment.
    ///
    /// Check this first. A fragment's header describes the fragment, and the fields
    /// that identify a stack, above all the window and options of the segment behind
    /// it, belong to a different piece of the datagram or are absent. A fragmented
    /// reply is evidence about the path, not the sender.
    pub fn is_fragment(self) -> bool {
        match self {
            // Only first fragments get this far: `parse_ip_segment` refuses a
            // non-zero fragment offset on both families, since what follows a later
            // fragment's header is mid-payload. That refusal is what makes the More
            // Fragments bit sufficient; the last fragment does not set it.
            IpObservation::V4(observed) => observed.more_fragments,
            // `walk_ipv6_headers` stops at a fragment header with a non-zero offset,
            // so only the first fragment arrives, and it cannot be told from a whole
            // datagram here. A caller that needs to know reads the extension header.
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
    /// Read for how it *changes* across replies: zero throughout, counting globally,
    /// counting per connection, and random are four policies, and which one a stack
    /// follows is close to a signature. Recorded per reply and read across them.
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
    /// Whether a stack sets one at all is the signal: the specification allows zero,
    /// several stacks always send zero, and others derive a value per flow.
    pub flow_label: u32,
}

/// What became of the frames a capture's BPF filter admitted, cumulative over its
/// lifetime, and whether it lasted the scan.
///
/// `dropped` matters most. It counts frames that matched the filter, reached the
/// kernel's buffer, and were discarded because this process did not read them in time.
/// A reply lost there is indistinguishable from a host that did not answer, and
/// retransmission does not help if the retry's reply is lost the same way, so the
/// scanner has to be told.
///
/// Compare against a scanner's own counters with care. The filters are narrow but not
/// private: the SYN filter admits every TCP SYN and RST crossing any captured
/// interface, so `received` includes unrelated traffic. It bounds the receive path's
/// load, not the scan's share of it.
#[non_exhaustive]
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
    /// How many captures ended before they were told to.
    ///
    /// Counted in captures, not frames. A capture whose reader stops leaves an
    /// interface deaf for the rest of the run, and every reply that would have arrived
    /// on it reads as a host that did not answer. Where [`dropped`](Self::dropped) says
    /// frames were lost, this says a link was, and the counts beside it describe less
    /// of the network than they appear to.
    ///
    /// A scan across eight interfaces reports how many of the eight went deaf.
    pub stopped_early: u64,
}

impl std::ops::Add for CaptureCounts {
    type Output = Self;

    /// Saturating, like every other count in the model: a wrapped total would read as
    /// a quiet capture.
    fn add(self, other: Self) -> Self {
        Self {
            received: self.received.saturating_add(other.received),
            dropped: self.dropped.saturating_add(other.dropped),
            if_dropped: self.if_dropped.saturating_add(other.if_dropped),
            stopped_early: self.stopped_early.saturating_add(other.stopped_early),
        }
    }
}

impl std::ops::AddAssign for CaptureCounts {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl std::iter::Sum for CaptureCounts {
    /// Totals a scan's captures. Empty sums to all zeros.
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
                stopped_early: 0,
            },
            CaptureCounts {
                received: 5,
                dropped: 0,
                if_dropped: 2,
                stopped_early: 0,
            },
        ]
        .into_iter()
        .sum();

        assert_eq!(total.received, 15);
        assert_eq!(total.dropped, 1);
        assert_eq!(total.if_dropped, 2);
    }

    /// A wrapped total would read as a quiet capture.
    #[test]
    fn a_total_too_large_to_represent_saturates_rather_than_wrapping() {
        let huge = CaptureCounts {
            received: u64::MAX,
            dropped: u64::MAX,
            if_dropped: u64::MAX,
            stopped_early: 0,
        };
        let one = CaptureCounts {
            received: 1,
            dropped: 1,
            if_dropped: 1,
            stopped_early: 0,
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
