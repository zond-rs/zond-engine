// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The route a probe took to reach a host
//!
//! [`NetworkPath`] is the sequence of routers between this machine and one
//! target: what a traceroute establishes, and the one finding in this engine
//! that describes the space *between* two addresses rather than either of them.
//!
//! ## A hop is a distance, not an index
//!
//! Every [`Hop`] carries the [`distance`](Hop::distance) it was measured at —
//! the hop limit whose expiry produced it — rather than being identified by its
//! position in a list. The two come apart constantly and the difference matters:
//!
//! - **A router may decline to answer.** Many do not send Time Exceeded at all,
//!   or rate-limit it to nothing. That leaves a gap, and a gap has to stay a gap:
//!   collapsing the list would silently renumber every router beyond it and
//!   report a five-hop path as four.
//! - **A path may be spliced.** When one trace recognises a router another trace
//!   already found, the rest is taken from the earlier one rather than measured
//!   again — see [`Hop::inferred`]. Those hops keep the distance they were
//!   originally measured at.
//!
//! So a path is stored sorted by distance, may have holes in it, and a reader
//! that wants "the third router" should ask for distance three rather than index
//! two.
//!
//! ## What a hop does and does not establish
//!
//! **It establishes that a router at that address discarded a packet of ours
//! that had travelled that far.** That is a strong statement: a router is
//! obliged to identify itself when it discards a packet (RFC 792, RFC 4443
//! §3.3), where it is under no obligation at all when it forwards one.
//!
//! **It does not establish that the router is *on* the path in any other
//! sense.** The address a router replies from is the one it chose, usually the
//! interface the probe arrived on but not always the same one on the way back.
//! Two traces to neighbouring hosts can name different addresses for what is
//! physically one device, and nothing here can tell.
//!
//! **A round-trip time is to the router, not between routers.** It is measured
//! from this machine, so hop three's timing includes hops one and two. It is
//! also the time a router took to generate an error, which many treat as the
//! lowest-priority work they do — a hop slower than the one after it is
//! ordinary and says nothing about the path.

use std::net::IpAddr;
use std::time::Duration;

/// One router on the way to a host, at a known distance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    distance: u8,
    address: Option<IpAddr>,
    rtt: Option<Duration>,
    inferred: bool,
}

impl Hop {
    /// A router that answered, at `distance` hops, in `rtt`.
    pub fn answered(distance: u8, address: IpAddr, rtt: Option<Duration>) -> Self {
        Self {
            distance,
            address: Some(address),
            rtt,
            inferred: false,
        }
    }

    /// A distance nothing answered at.
    ///
    /// Recorded rather than omitted, because the two are different findings and
    /// only one of them is about the network. A missing entry would say the path
    /// is shorter than it is; this says a router is there and would not say so.
    pub fn silent(distance: u8) -> Self {
        Self {
            distance,
            address: None,
            rtt: None,
            inferred: false,
        }
    }

    /// The same hop, marked as taken from another host's trace rather than
    /// measured on this one. See [`inferred`](Self::inferred).
    #[must_use]
    pub fn as_inferred(mut self) -> Self {
        self.inferred = true;
        // A round trip belongs to the trace that measured it. Carrying one
        // across would report a timing for a probe this host never drew.
        self.rtt = None;
        self
    }

    /// How many hops from this machine this router sits.
    pub fn distance(&self) -> u8 {
        self.distance
    }

    /// The address the router answered from, or `None` if nothing answered at
    /// this distance.
    pub fn address(&self) -> Option<IpAddr> {
        self.address
    }

    /// How long the probe that expired here took to be answered, measured from
    /// this machine. `None` for a silent hop, and for an inferred one.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Whether this hop was measured on the way to *this* host, or copied from
    /// an earlier trace that passed through the same router.
    ///
    /// Not decoration. A path assembled partly from another host's trace is a
    /// weaker claim than one probed end to end — the two hosts were assumed to
    /// share everything upstream of the router where the traces met, which is
    /// true of nearly every network and is still an assumption. A reader acting
    /// on a single hop should know which kind they are looking at, and a report
    /// that did not distinguish them would present an inference as a
    /// measurement.
    pub fn inferred(&self) -> bool {
        self.inferred
    }
}

/// The routers between this machine and one host, in order of distance.
///
/// Sorted by distance and holding at most one hop per distance. Both invariants
/// are established by [`record`](Self::record) and nothing else can break them,
/// since there is no other way in.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetworkPath {
    hops: Vec<Hop>,
}

impl NetworkPath {
    /// An empty path.
    pub fn new() -> Self {
        Self::default()
    }

    /// Records `hop`, replacing whatever was known at that distance.
    ///
    /// **A measurement replaces an inference and never the reverse.** A trace
    /// that spliced in another host's hops and then measured one of them for
    /// itself has learned something; the same in reverse would throw away the
    /// stronger of two claims about the same router. An answered hop likewise
    /// replaces a silent one, since silence is the absence of a finding rather
    /// than a finding of absence.
    pub fn record(&mut self, hop: Hop) {
        match self
            .hops
            .binary_search_by_key(&hop.distance, |known| known.distance)
        {
            Ok(index) => {
                let known = &self.hops[index];
                let stronger = (known.inferred && !hop.inferred)
                    || (known.address.is_none() && hop.address.is_some());
                if stronger {
                    self.hops[index] = hop;
                }
            }
            Err(index) => self.hops.insert(index, hop),
        }
    }

    /// Every hop, ascending by distance. May have gaps; see the module docs.
    pub fn hops(&self) -> &[Hop] {
        &self.hops
    }

    /// Whether anything is known about the path at all.
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }

    /// How far away the furthest known router is, or `None` for an empty path.
    ///
    /// The last *known* distance rather than a count of hops, which differ
    /// whenever a router declined to answer.
    pub fn length(&self) -> Option<u8> {
        self.hops.last().map(Hop::distance)
    }

    /// The address at `distance`, if a router answered there.
    pub fn at(&self, distance: u8) -> Option<IpAddr> {
        self.hops
            .binary_search_by_key(&distance, |hop| hop.distance)
            .ok()
            .and_then(|index| self.hops[index].address)
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
    use std::net::Ipv4Addr;

    fn ip(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
    }

    /// Hops arrive in whatever order their replies do, and a path reads in
    /// order of distance regardless.
    ///
    /// Traces run their probes concurrently, so hop five is answered before hop
    /// two often enough that ordering on arrival would be the common case rather
    /// than the odd one.
    #[test]
    fn a_path_reads_in_order_of_distance_however_the_replies_arrived() {
        let mut path = NetworkPath::new();
        path.record(Hop::answered(3, ip(3), None));
        path.record(Hop::answered(1, ip(1), None));
        path.record(Hop::answered(2, ip(2), None));

        let distances: Vec<u8> = path.hops().iter().map(Hop::distance).collect();
        assert_eq!(distances, vec![1, 2, 3]);
        assert_eq!(path.length(), Some(3));
        assert_eq!(path.at(2), Some(ip(2)));
    }

    /// A router that will not answer leaves a hole, and the hole is the finding.
    ///
    /// Dropping it would renumber everything past it: this path would read as
    /// two hops long when the target is three routers away.
    #[test]
    fn a_silent_router_holds_its_place() {
        let mut path = NetworkPath::new();
        path.record(Hop::answered(1, ip(1), None));
        path.record(Hop::silent(2));
        path.record(Hop::answered(3, ip(3), None));

        assert_eq!(path.hops().len(), 3);
        assert_eq!(path.at(2), None);
        assert_eq!(path.length(), Some(3), "the target is still three away");
    }

    /// What is known about a distance only ever gets stronger.
    ///
    /// The three transitions that must hold, and the three that must not. A
    /// trace which splices another host's hops and then measures one for itself
    /// has to keep the measurement; the same events in the other order must not
    /// throw it away, and reply ordering decides which order they arrive in.
    #[test]
    fn a_measurement_outranks_an_inference_and_an_answer_outranks_silence() {
        let measured = Hop::answered(2, ip(2), Some(Duration::from_millis(5)));
        let inferred = Hop::answered(2, ip(9), None).as_inferred();

        let mut upgrading = NetworkPath::new();
        upgrading.record(inferred);
        upgrading.record(measured);
        assert_eq!(upgrading.at(2), Some(ip(2)));
        assert!(!upgrading.hops()[0].inferred());

        let mut downgrading = NetworkPath::new();
        downgrading.record(measured);
        downgrading.record(inferred);
        assert_eq!(downgrading.at(2), Some(ip(2)), "a measurement is not lost");
        assert_eq!(downgrading.hops()[0].rtt(), Some(Duration::from_millis(5)));

        let mut filling = NetworkPath::new();
        filling.record(Hop::silent(2));
        filling.record(measured);
        assert_eq!(filling.at(2), Some(ip(2)));

        let mut keeping = NetworkPath::new();
        keeping.record(measured);
        keeping.record(Hop::silent(2));
        assert_eq!(
            keeping.at(2),
            Some(ip(2)),
            "silence does not erase an answer"
        );
    }

    /// An inferred hop carries no round-trip time, because the probe that
    /// produced one was sent to somewhere else.
    #[test]
    fn an_inferred_hop_reports_no_timing_of_its_own() {
        let inferred = Hop::answered(4, ip(4), Some(Duration::from_millis(9))).as_inferred();

        assert!(inferred.inferred());
        assert_eq!(inferred.address(), Some(ip(4)));
        assert_eq!(inferred.rtt(), None);
    }
}
