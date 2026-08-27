// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Evasion: choosing what a scan puts on the wire
//!
//! Controls what a scan sends so a probe can draw an answer an ordinary one
//! would not: a probe from a source port a filter trusts, a chosen hop limit,
//! padding that moves a probe off a recognisable size, a checksum built wrong so
//! that only a middlebox would answer it. Set the fields you want on an
//! [`EvasionProfile`] and hand it to the scan configuration.
//!
//! A default profile changes nothing — a scan configured with one puts the same
//! packets on the wire, byte for byte, as a scan configured without it — so
//! evasion is never something a scan does by accident.

use crate::transport::probe::Emission;

/// What a scan changes about the packets it sends, over the engine's defaults.
///
/// A default profile is inert — see the [module documentation](self). Set a
/// field for each technique you want; [`is_active`](Self::is_active) reports
/// whether any is set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvasionProfile {
    /// The source port every probe leaves from, replacing the port the engine
    /// would otherwise choose.
    ///
    /// A great many stateless filters still trust a source port: a rule that
    /// permits "returning DNS" permits anything from port 53, and one that trusts
    /// a zone transfer trusts port 20. A probe sent from such a port walks through
    /// the filter the way the traffic it is impersonating would.
    ///
    /// `None` keeps the engine's own choice, which is not one value: the raw TCP
    /// scanner randomises a fresh high port per probe, and the UDP scanner holds
    /// one high port for the scan. Setting this replaces *both* with the chosen
    /// port — one profile shaping every packet — so a scan pins its source port
    /// everywhere a source port is chosen, the connect path included.
    pub source_port: Option<u16>,

    /// The hop limit (IPv4 TTL / IPv6 hop limit) written into every ordinary
    /// probe, replacing the routed default.
    ///
    /// Set to defeat a filter or IDS that keys on hop count, or to place a probe
    /// so it expires at a chosen distance. `None` keeps
    /// [`HOP_LIMIT_ROUTED`](crate::protocols::ip::HOP_LIMIT_ROUTED), which is
    /// enough for any path on the public internet.
    ///
    /// This governs the probes a scan sends to *reach* a host. It does not touch
    /// path measurement: a traceroute exists precisely to vary the hop limit hop
    /// by hop, and reads the value back out of the errors that return, so it sets
    /// its own and ignores this one. Overriding traceroute's hop limit from here
    /// would not be evasion; it would be breaking the instrument.
    pub ttl: Option<u8>,

    /// How many extra random bytes every probe carries on the end of its
    /// payload, on top of whatever it would otherwise send.
    ///
    /// A bare SYN is a fixed forty bytes and an empty UDP probe a fixed eight,
    /// and a signature or a middlebox rule can key on exactly that size. A run
    /// of random bytes on the end moves the probe off it. The bytes are random
    /// rather than zero because a run of zeroes is itself the kind of fixed
    /// pattern this exists to escape.
    ///
    /// Applies to TCP and UDP probes alike — appending data to a SYN is unusual,
    /// which is the point. `None` appends nothing, and every probe is the exact
    /// size it has always been.
    pub padding: Option<u16>,

    /// Whether every TCP probe leaves carrying a checksum that is deliberately
    /// wrong.
    ///
    /// A conformant host drops a segment whose TCP checksum does not verify, so
    /// a reply to one was not sent by the host — it was sent by something in the
    /// path that answered without checking: a firewall, an intrusion-prevention
    /// system, a load balancer. The corrupt checksum crosses the whole path and
    /// is discarded at the far end, so a reply implicates a middlebox anywhere
    /// along it rather than testing only the local segment.
    ///
    /// Scoped to TCP, as the name says: the checksum it corrupts is the TCP one,
    /// and a UDP scan is simply unaffected. `false` sends the checksum a host
    /// will accept.
    pub bad_tcp_checksum: bool,
}

impl EvasionProfile {
    /// Whether this profile changes anything — `false` for a default profile.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self != Self::default()
    }

    /// The source port a probe should leave from: the [`source_port`] override
    /// if one is set, otherwise `default` — the port the engine would have
    /// chosen itself.
    ///
    /// [`source_port`]: Self::source_port
    #[must_use]
    pub fn source_port_or(&self, default: u16) -> u16 {
        self.source_port.unwrap_or(default)
    }

    /// The [`Emission`] an ordinary probe should carry: the routed default, with
    /// the hop limit replaced when [`ttl`](Self::ttl) is set. Path measurement
    /// chooses its own hop limit and does not use this.
    #[must_use]
    pub fn emission(&self) -> Emission {
        match self.ttl {
            Some(hop_limit) => Emission::routed().with_hop_limit(hop_limit),
            None => Emission::routed(),
        }
    }

    /// The [`SegmentShaping`] every probe should carry — the
    /// [`padding`](Self::padding) and [`bad_tcp_checksum`](Self::bad_tcp_checksum)
    /// choices as one value.
    #[must_use]
    pub fn segment_shaping(&self) -> SegmentShaping {
        SegmentShaping {
            padding: self.padding,
            bad_tcp_checksum: self.bad_tcp_checksum,
        }
    }

    /// Sets the [source port](Self::source_port) every probe leaves from.
    #[must_use]
    pub fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    /// Sets the [hop limit](Self::ttl) every ordinary probe carries.
    #[must_use]
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets the number of random [padding](Self::padding) bytes every probe
    /// appends to its payload.
    #[must_use]
    pub fn with_padding(mut self, padding: u16) -> Self {
        self.padding = Some(padding);
        self
    }

    /// Sets whether every TCP probe carries a
    /// [deliberately wrong checksum](Self::bad_tcp_checksum).
    #[must_use]
    pub fn with_bad_tcp_checksum(mut self, corrupt: bool) -> Self {
        self.bad_tcp_checksum = corrupt;
        self
    }
}

/// The segment-level evasion a scan applies to every probe: the choices that
/// live in the L4 segment rather than the IP header around it. Produced by
/// [`EvasionProfile::segment_shaping`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentShaping {
    /// How many random bytes to append to the probe's payload, or `None` for
    /// none. See [`EvasionProfile::padding`].
    pub padding: Option<u16>,

    /// Whether a TCP probe carries a deliberately wrong checksum. Read only by
    /// the TCP send paths; a UDP probe ignores it, as the name says. See
    /// [`EvasionProfile::bad_tcp_checksum`].
    pub bad_tcp_checksum: bool,
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
    fn a_default_profile_is_inert() {
        // The whole trust argument rests on this: a scan that asked for no
        // evasion must be indistinguishable from one predating the module. A
        // mutant that reported `is_active` for a fresh profile would let an
        // ordinary scan grow an evasion record it never earned.
        assert!(!EvasionProfile::default().is_active());
    }

    #[test]
    fn setting_any_field_makes_the_profile_active() {
        assert!(EvasionProfile::default().with_source_port(53).is_active());
        assert!(EvasionProfile::default().with_ttl(32).is_active());
        assert!(EvasionProfile::default().with_padding(16).is_active());
        assert!(
            EvasionProfile::default()
                .with_bad_tcp_checksum(true)
                .is_active()
        );
    }

    #[test]
    fn a_builder_records_exactly_what_it_was_given() {
        let profile = EvasionProfile::default()
            .with_source_port(53)
            .with_ttl(32)
            .with_padding(16)
            .with_bad_tcp_checksum(true);
        assert_eq!(profile.source_port, Some(53));
        assert_eq!(profile.ttl, Some(32));
        assert_eq!(profile.padding, Some(16));
        assert!(profile.bad_tcp_checksum);
    }

    #[test]
    fn source_port_resolves_to_the_override_when_set_and_the_default_otherwise() {
        // The rule every source-port site depends on. A mutant that returned the
        // default even when the caller set an override would silently un-pin the
        // source port of every scan that asked for one — the whole point of the
        // knob — while every construction still compiled and ran.
        assert_eq!(EvasionProfile::default().source_port_or(50_000), 50_000);
        assert_eq!(
            EvasionProfile::default()
                .with_source_port(53)
                .source_port_or(50_000),
            53
        );
    }

    #[test]
    fn emission_carries_the_ttl_override_and_the_routed_default_otherwise() {
        // The override has to reach the hop limit and nothing else. A mutant
        // that returned the routed default regardless would leave a scan that
        // asked to look like it was three hops away sending the ordinary 64,
        // defeating exactly the hop-count evasion the caller set.
        assert_eq!(EvasionProfile::default().emission(), Emission::routed());
        assert_eq!(
            EvasionProfile::default().with_ttl(7).emission().hop_limit,
            7
        );
    }

    #[test]
    fn segment_shaping_carries_the_overrides_and_nothing_by_default() {
        // A default profile shapes no segment: the inert invariant every send
        // path leans on. A mutant whose default carried padding or a bad
        // checksum would corrupt every probe of a scan that asked for neither.
        assert_eq!(
            EvasionProfile::default().segment_shaping(),
            SegmentShaping::default()
        );

        // Each override has to reach the field it names. A mutant that dropped
        // the padding would send a bare probe where the caller asked for a
        // padded one, and one that dropped the checksum flag would send a valid
        // checksum where the caller asked for a corrupt one — silently undoing
        // the very knob that was set, while every construction still compiled.
        let shaping = EvasionProfile::default()
            .with_padding(16)
            .with_bad_tcp_checksum(true)
            .segment_shaping();
        assert_eq!(shaping.padding, Some(16));
        assert!(shaping.bad_tcp_checksum);
    }
}
