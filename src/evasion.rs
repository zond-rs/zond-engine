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

use std::net::IpAddr;

use crate::config::SendMode;
use crate::model::mac::MacAddr;
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

    /// The hardware address every frame claims to come from, replacing the
    /// sending interface's own.
    ///
    /// For NAC and MAC-filtering tests on the local segment. It is meaningful
    /// only there — a router rewrites the source hardware address at the first
    /// hop — and only over a self-built Ethernet frame, so setting it makes a
    /// scan open the link-layer send path (see
    /// [`effective_send_mode`](Self::effective_send_mode)); a destination the
    /// Ethernet path cannot reach, such as loopback, is refused. `None` uses the
    /// interface's own address.
    pub spoof_mac: Option<MacAddr>,

    /// The largest each IP fragment a probe is split into may be, in bytes, or
    /// `None` to send probes whole.
    ///
    /// Splits the IP packet so a stateless filter or cheap IDS keyed on a whole
    /// TCP header never sees one. IPv4 only, and only over a self-built Ethernet
    /// frame, so setting it opens the link-layer send path (see
    /// [`effective_send_mode`](Self::effective_send_mode)). An IPv6 destination,
    /// or a value too small to carry a header and a fragment, is refused.
    pub fragment: Option<u16>,

    /// Source addresses to send a copy of every probe from, alongside the real
    /// one, so an observer sees several apparent scanners and cannot tell which
    /// is real.
    ///
    /// Each real probe goes out among its decoys in random order. A decoy is
    /// built from its own address with its own checksum, so it is not the odd
    /// one out that carries a wrong one, and it is never recorded — a decoy's
    /// reply can never resolve a port. Spoofing a source address needs a
    /// self-built Ethernet frame, so setting this opens the link-layer path (see
    /// [`effective_send_mode`](Self::effective_send_mode)); and egress filtering
    /// drops spoofed-source packets before they leave a well-run network, so
    /// decoys are most effective on the local segment. Only decoys of a target's
    /// own address family are used against it. Empty sends probes from this host
    /// alone.
    pub decoys: Vec<IpAddr>,

    /// The exact TCP flag byte every port probe carries, replacing the
    /// combination the scan technique would otherwise send, or `None` to send
    /// the technique's own.
    ///
    /// The six named techniques are a curated menu — each a flag combination
    /// with a defined open/closed meaning. This opens the whole space instead,
    /// for the diagnostic worth of a combination a filter or a stack has no
    /// settled answer to. The cost is exactly that: an arbitrary combination
    /// carries no such meaning, so a port probed with one is read only as
    /// *reachable* (something answered) or *silent*, never open or closed. The
    /// bits are those of [`crate::protocols::tcp::flags`].
    ///
    /// This shapes the TCP port scan alone. Host discovery, the OS-detection
    /// probes and the firewall-characterisation pass each send a segment whose
    /// exact shape is the measurement, so none of them takes an overriding flag.
    pub flags: Option<u8>,
}

impl EvasionProfile {
    /// Whether this profile changes anything — `false` for a default profile.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self != Self::default()
    }

    /// Whether this profile can only be honoured over a self-built Ethernet
    /// frame, because it sets a field the raw-socket path cannot place: a
    /// spoofed hardware address, fragments this engine chose rather than the
    /// kernel, or decoys sent from spoofed source addresses.
    #[must_use]
    pub fn requires_link_layer(&self) -> bool {
        self.spoof_mac.is_some() || self.fragment.is_some() || !self.decoys.is_empty()
    }

    /// The send mode a scan should actually open, given the one it asked for.
    ///
    /// A framing technique can only leave as a self-built Ethernet frame, so
    /// [`SendMode::Auto`] resolves to [`SendMode::Ethernet`] when this profile
    /// sets one. Every explicit choice is left as the caller made it: a raw
    /// socket that cannot carry the technique is refused per probe rather than
    /// silently overridden.
    #[must_use]
    pub fn effective_send_mode(&self, requested: SendMode) -> SendMode {
        if self.requires_link_layer() && matches!(requested, SendMode::Auto) {
            SendMode::Ethernet
        } else {
            requested
        }
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

    /// The [`Emission`] an ordinary probe should carry: the routed default, plus
    /// the hop limit from [`ttl`](Self::ttl), the source hardware address from
    /// [`spoof_mac`](Self::spoof_mac), and the fragment size from
    /// [`fragment`](Self::fragment), each when it is set. Path measurement
    /// chooses its own hop limit and does not use this.
    #[must_use]
    pub fn emission(&self) -> Emission {
        let mut emission = self.hop_limited_emission();
        emission.source_mac = self.spoof_mac;
        emission.fragment = self.fragment;
        emission
    }

    /// The emission for a probe that should carry the chosen hop limit but must
    /// not be reshaped in any other way.
    ///
    /// This is what an OS-detection or path-measurement probe takes from the
    /// profile. Such a probe should expire at the same distance as every other —
    /// so it honours the hop limit — but its answer *is* the measurement, and a
    /// framing technique would change that answer: a fragmented or spoofed probe
    /// would have the engine reading its own evasion back instead of the host.
    /// So the framing state a full [`emission`](Self::emission) carries — the
    /// spoofed hardware address and the fragmentation — is deliberately left off.
    pub fn hop_limited_emission(&self) -> Emission {
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

    /// Sets the [hardware address](Self::spoof_mac) every frame claims to come
    /// from.
    #[must_use]
    pub fn with_spoof_mac(mut self, mac: MacAddr) -> Self {
        self.spoof_mac = Some(mac);
        self
    }

    /// Sets the largest each [IP fragment](Self::fragment) a probe is split into
    /// may be, in bytes.
    #[must_use]
    pub fn with_fragment(mut self, mtu: u16) -> Self {
        self.fragment = Some(mtu);
        self
    }

    /// Sets the [decoy](Self::decoys) source addresses every probe is copied
    /// from.
    #[must_use]
    pub fn with_decoys(mut self, decoys: Vec<IpAddr>) -> Self {
        self.decoys = decoys;
        self
    }

    /// Sets the exact [TCP flag byte](Self::flags) every port probe carries.
    #[must_use]
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = Some(flags);
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
        assert!(
            EvasionProfile::default()
                .with_spoof_mac(MacAddr::new(2, 0, 0, 0, 0, 1))
                .is_active()
        );
        assert!(EvasionProfile::default().with_fragment(28).is_active());
        assert!(
            EvasionProfile::default()
                .with_decoys(vec!["10.0.0.9".parse().unwrap()])
                .is_active()
        );
    }

    #[test]
    fn a_builder_records_exactly_what_it_was_given() {
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        let profile = EvasionProfile::default()
            .with_source_port(53)
            .with_ttl(32)
            .with_padding(16)
            .with_bad_tcp_checksum(true)
            .with_spoof_mac(mac)
            .with_fragment(28)
            .with_decoys(vec!["10.0.0.9".parse().unwrap()]);
        assert_eq!(profile.source_port, Some(53));
        assert_eq!(profile.ttl, Some(32));
        assert_eq!(profile.padding, Some(16));
        assert!(profile.bad_tcp_checksum);
        assert_eq!(profile.spoof_mac, Some(mac));
        assert_eq!(profile.fragment, Some(28));
        assert_eq!(profile.decoys, vec!["10.0.0.9".parse::<IpAddr>().unwrap()]);
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
    fn emission_carries_the_spoofed_hardware_address() {
        // The spoofed address has to reach the emission the send path reads, and
        // it makes that emission one only a self-built frame can carry. A mutant
        // that left `source_mac` off the emission would send every frame from the
        // interface's own address while the scan still claimed to have spoofed.
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        let emission = EvasionProfile::default().with_spoof_mac(mac).emission();
        assert_eq!(emission.source_mac, Some(mac));
        assert!(emission.requires_link_layer());

        // A fragment size is the other framing field: it reaches the emission
        // and it too forces the link layer.
        let emission = EvasionProfile::default().with_fragment(28).emission();
        assert_eq!(emission.fragment, Some(28));
        assert!(emission.requires_link_layer());

        assert_eq!(EvasionProfile::default().emission().source_mac, None);
        assert_eq!(EvasionProfile::default().emission().fragment, None);
        assert!(!EvasionProfile::default().emission().requires_link_layer());
    }

    #[test]
    fn a_hop_limited_emission_carries_the_hop_limit_but_never_reshapes() {
        // What an OS-detection or path-measurement probe takes from the profile:
        // the hop limit, so it expires like every other probe — and only that. A
        // mutant that reused the full `emission` here would fragment or spoof the
        // very probe whose reply is the measurement, and the engine would read
        // its own evasion back instead of the host.
        assert_eq!(
            EvasionProfile::default().hop_limited_emission(),
            Emission::routed(),
        );

        let profile = EvasionProfile::default()
            .with_ttl(7)
            .with_spoof_mac(MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01))
            .with_fragment(28);
        let emission = profile.hop_limited_emission();

        assert_eq!(emission.hop_limit, 7, "the chosen hop limit is carried");
        assert_eq!(emission.source_mac, None, "no spoofed address reshapes it");
        assert_eq!(emission.fragment, None, "no fragmentation reshapes it");
        assert!(
            !emission.requires_link_layer(),
            "so a measurement probe stays on whatever path its phase opened"
        );
    }

    #[test]
    fn auto_becomes_ethernet_only_when_a_framing_technique_is_set() {
        let plain = EvasionProfile::default();
        let framing = EvasionProfile::default().with_spoof_mac(MacAddr::new(2, 0, 0, 0, 0, 1));

        // A framing technique forces Auto onto the link layer, or the raw sender
        // it would otherwise pick refuses every probe.
        assert_eq!(
            framing.effective_send_mode(SendMode::Auto),
            SendMode::Ethernet
        );
        // Nothing else is touched: an ordinary scan keeps Auto, and an explicit
        // choice is left as the caller made it even when it cannot carry the
        // technique — refused per probe, not silently overridden.
        assert_eq!(plain.effective_send_mode(SendMode::Auto), SendMode::Auto);
        assert_eq!(
            framing.effective_send_mode(SendMode::RawSocket),
            SendMode::RawSocket
        );
        assert_eq!(
            plain.effective_send_mode(SendMode::Ethernet),
            SendMode::Ethernet
        );

        // Fragmentation is a framing technique too, so it forces Auto onto the
        // link layer the same way a spoofed MAC does.
        assert_eq!(
            EvasionProfile::default()
                .with_fragment(28)
                .effective_send_mode(SendMode::Auto),
            SendMode::Ethernet
        );

        // Decoys spoof a source address, which only a self-built frame carries,
        // so they force the link layer as well.
        assert_eq!(
            EvasionProfile::default()
                .with_decoys(vec!["10.0.0.9".parse().unwrap()])
                .effective_send_mode(SendMode::Auto),
            SendMode::Ethernet
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
