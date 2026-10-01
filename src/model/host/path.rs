// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The route a probe took to reach a host
//!
//! [`NetworkPath`] is the sequence of routers between this machine and one target, as
//! a traceroute establishes it: a finding about the space *between* two addresses.
//!
//! ## A hop is a distance
//!
//! Every [`Hop`] carries the [`distance`](Hop::distance) it was measured at (the hop
//! limit whose expiry produced it), independent of its position in the list:
//!
//! - **A router may decline to answer.** Many never send Time Exceeded, or rate-limit
//!   it to nothing. The gap stays, so routers beyond it keep their numbers.
//! - **A path may be spliced.** When one trace meets a router another trace found, the
//!   rest is taken from the earlier trace; see [`Hop::inferred`]. Those hops keep their
//!   original distances.
//!
//! So a path is sorted by distance and may have holes; ask for distance three, not
//! index two.
//!
//! ## A router the scan may not name
//!
//! A router whose address falls under the scan's
//! [`Exclusions`](crate::model::exclusion::Exclusions) keeps its distance and loses its
//! address; see [`Hop::withheld`]. A trace hears from such a router without sending to
//! it, so recording is the only part of the policy a path could break. Recording it as
//! silent would claim nothing answered, and leaving it out could make the path read a
//! router shorter.
//!
//! ## What a hop establishes
//!
//! A router at that address discarded a packet of ours that had travelled that far. A
//! router must identify itself when it discards a packet (RFC 792, RFC 4443 §3.3).
//!
//! The address is the one the router chose to reply from, not always the interface
//! the probe used, so two traces can name different addresses for one device.
//!
//! A round-trip time is measured from this machine to the router, so hop three's
//! includes hops one and two. Routers treat generating errors as low priority, so a hop
//! slower than the next is ordinary.

use std::net::IpAddr;
use std::time::Duration;

/// One router on the way to a host, at a known distance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Hop {
    distance: u8,
    answer: Answer,
    rtt: Option<Duration>,
    inferred: bool,
}

/// What was heard from a distance.
///
/// One value, so a withheld hop carrying an address cannot be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    /// Nothing answered.
    Silent,
    /// A router answered, from this address.
    Router(IpAddr),
    /// A router answered, from an address the scan may not report.
    Withheld,
}

impl Hop {
    /// A router that answered, at `distance` hops, in `rtt`.
    pub fn answered(distance: u8, address: IpAddr, rtt: Option<Duration>) -> Self {
        Self {
            distance,
            answer: Answer::Router(address),
            rtt,
            inferred: false,
        }
    }

    /// A distance nothing answered at.
    ///
    /// Recorded, since omitting it would make the path read shorter than it is.
    pub fn silent(distance: u8) -> Self {
        Self {
            distance,
            answer: Answer::Silent,
            rtt: None,
            inferred: false,
        }
    }

    /// A distance a router answered at, from an address the scan's exclusions
    /// forbid it to report.
    ///
    /// See the module documentation. Carries no round trip, which would be a fact about
    /// the router.
    ///
    /// For reading a record back; a scan records a router as it answered and withholds
    /// the address afterwards.
    pub fn withheld(distance: u8) -> Self {
        Self {
            distance,
            answer: Answer::Withheld,
            rtt: None,
            inferred: false,
        }
    }

    /// The same hop, marked as taken from another host's trace rather than
    /// measured on this one. See [`inferred`](Self::inferred).
    #[must_use]
    pub fn as_inferred(mut self) -> Self {
        self.inferred = true;
        // A round trip belongs to the trace that measured it.
        self.rtt = None;
        self
    }

    /// How many hops from this machine this router sits.
    pub fn distance(&self) -> u8 {
        self.distance
    }

    /// The address the router answered from, or `None` if nothing answered at
    /// this distance or the address is [withheld](Self::is_withheld).
    pub fn address(&self) -> Option<IpAddr> {
        match self.answer {
            Answer::Router(address) => Some(address),
            Answer::Silent | Answer::Withheld => None,
        }
    }

    /// How long the probe that expired here took to be answered, measured from
    /// this machine. `None` for a silent hop, an inferred one and a withheld
    /// one.
    pub fn rtt(&self) -> Option<Duration> {
        self.rtt
    }

    /// Whether a router answered here from an address the scan may not report.
    ///
    /// The one case where [`address`](Self::address) is `None` but something answered,
    /// so check it before drawing a gap. See [`withheld`](Self::withheld).
    pub fn is_withheld(&self) -> bool {
        self.answer == Answer::Withheld
    }

    /// Whether anything answered at this distance, whether or not the report
    /// may say what.
    fn is_answer(&self) -> bool {
        self.answer != Answer::Silent
    }

    /// Whether this hop was measured on the way to *this* host, or copied from
    /// an earlier trace that passed through the same router.
    ///
    /// A spliced path assumes the two hosts share everything upstream of the router
    /// where the traces met, which is nearly always true but still an assumption.
    pub fn inferred(&self) -> bool {
        self.inferred
    }
}

/// The routers between this machine and one host, in order of distance.
///
/// Sorted by distance, with at most one hop per distance. [`record`](Self::record) is
/// the only way in; withholding an address rewrites a hop in place.
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
    /// An answered hop replaces a silent one, since silence is the absence of a
    /// finding. Between two that agree on that, a measurement replaces an inference
    /// and never the reverse. A [withheld](Hop::withheld) hop counts as answered.
    pub fn record(&mut self, hop: Hop) {
        match self
            .hops
            .binary_search_by_key(&hop.distance, |known| known.distance)
        {
            Ok(index) => {
                let known = &self.hops[index];
                // Ranked: whether anything answered first, then provenance.
                // Otherwise a measured silence could displace an inferred answer,
                // which `Host::merge` replaying hops in either order would reach.
                let stronger = match (known.is_answer(), hop.is_answer()) {
                    (false, true) => true,
                    (true, false) => false,
                    _ => known.inferred && !hop.inferred,
                };
                if stronger {
                    self.hops[index] = hop;
                }
            }
            Err(index) => self.hops.insert(index, hop),
        }
    }

    /// Withholds the address of every router `keep` refuses, and returns
    /// whether it withheld any.
    ///
    /// For the exclusion policy. Each refused hop becomes [`Hop::withheld`] at the same
    /// distance and provenance, losing its round trip with its address.
    pub(crate) fn withhold(&mut self, keep: impl Fn(&IpAddr) -> bool) -> bool {
        let mut withheld = false;
        for hop in &mut self.hops {
            if let Answer::Router(address) = hop.answer
                && !keep(&address)
            {
                *hop = Hop {
                    inferred: hop.inferred,
                    ..Hop::withheld(hop.distance)
                };
                withheld = true;
            }
        }
        withheld
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
    /// The last *known* distance, which differs from a hop count when a router
    /// declined to answer.
    pub fn length(&self) -> Option<u8> {
        self.hops.last().map(Hop::distance)
    }

    /// The address at `distance`, if a router answered there and its address
    /// is not withheld.
    pub fn at(&self, distance: u8) -> Option<IpAddr> {
        self.hops
            .binary_search_by_key(&distance, |hop| hop.distance)
            .ok()
            .and_then(|index| self.hops[index].address())
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

    /// An answer displaces silence whatever measured it, and provenance decides
    /// only between two hops that agree about whether anything answered.
    ///
    /// A measured silent hop does not displace an inferred answered one.
    #[test]
    fn an_answer_is_never_traded_for_a_silence_that_measured_it() {
        let spliced = Hop::answered(4, ip(4), None).as_inferred();

        let mut path = NetworkPath::new();
        path.record(spliced);
        path.record(Hop::silent(4));
        assert_eq!(
            path.at(4),
            Some(ip(4)),
            "a measured silence does not erase a router somebody found"
        );

        // The other way round.
        let mut reverse = NetworkPath::new();
        reverse.record(Hop::silent(4));
        reverse.record(spliced);
        assert_eq!(reverse.at(4), Some(ip(4)));

        // Where both answered, the measurement wins.
        let mut both = NetworkPath::new();
        both.record(Hop::answered(1, ip(9), None).as_inferred());
        both.record(Hop::answered(1, ip(1), None));
        assert_eq!(both.at(1), Some(ip(1)), "a measurement beats an inference");

        // Where neither did, the measurement stands.
        let mut neither = NetworkPath::new();
        neither.record(Hop::silent(2));
        neither.record(Hop::silent(2).as_inferred());
        assert_eq!(neither.hops().len(), 1);
        assert!(!neither.hops()[0].inferred());
    }

    /// Hops arrive in whatever order their replies do, and a path reads in
    /// order of distance regardless.
    ///
    /// Traces probe concurrently, so hop five often answers before hop two.
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
    /// Dropping it would make this three-router path read as two.
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
    /// The three transitions that must hold, and the three that must not, in either
    /// arrival order.
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

    /// A withheld router ranks as the answer it was, not as the silence its
    /// missing address resembles.
    ///
    /// A measured silence does not displace a spliced router whose address was
    /// withheld.
    #[test]
    fn a_withheld_router_still_outranks_silence() {
        let spliced = Hop::withheld(3).as_inferred();

        let mut path = NetworkPath::new();
        path.record(spliced);
        path.record(Hop::silent(3));
        assert!(path.hops()[0].is_withheld(), "{path:?}");

        // Between two answers, provenance still decides.
        let mut measured = NetworkPath::new();
        measured.record(Hop::answered(3, ip(3), None).as_inferred());
        measured.record(Hop::withheld(3));
        assert!(measured.hops()[0].is_withheld());
        assert!(!measured.hops()[0].inferred());
    }

    /// Withholding keeps the distance and provenance and drops the address and round
    /// trip.
    #[test]
    fn withholding_a_router_keeps_its_place_and_its_provenance() {
        let mut path = NetworkPath::new();
        path.record(Hop::answered(1, ip(1), Some(Duration::from_millis(1))));
        path.record(Hop::answered(2, ip(2), Some(Duration::from_millis(2))).as_inferred());
        path.record(Hop::answered(3, ip(3), Some(Duration::from_millis(3))));

        assert!(path.withhold(|address| *address != ip(2)));

        let withheld = path.hops()[1];
        assert_eq!(withheld.distance(), 2);
        assert!(withheld.is_withheld());
        assert!(withheld.inferred(), "a spliced router stays marked as one");
        assert_eq!(withheld.address(), None);
        assert_eq!(withheld.rtt(), None);
        assert_eq!(path.at(1), Some(ip(1)), "a permitted router is untouched");
        assert_eq!(path.length(), Some(3));

        assert!(
            !path.withhold(|address| *address != ip(2)),
            "there is nothing left to withhold"
        );
    }

    /// An inferred hop carries no round-trip time.
    #[test]
    fn an_inferred_hop_reports_no_timing_of_its_own() {
        let inferred = Hop::answered(4, ip(4), Some(Duration::from_millis(9))).as_inferred();

        assert!(inferred.inferred());
        assert_eq!(inferred.address(), Some(ip(4)));
        assert_eq!(inferred.rtt(), None);
    }
}
