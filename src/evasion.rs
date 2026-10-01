// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Evasion: choosing what a scan puts on the wire
//!
//! Shapes the probes a scan sends so they draw answers ordinary probes would
//! not: a source port a filter trusts, a chosen hop limit, padding that moves a
//! probe off a recognisable size, a checksum built wrong so only a middlebox
//! answers. Set the fields you need on an [`EvasionProfile`] and put it in the
//! scan configuration.
//!
//! A default profile changes nothing: the scan sends the same bytes as one
//! configured without it.
//!
//! ```
//! use zond_engine::{EvasionProfile, ZondConfig};
//!
//! // From the port a filter trusts for DNS replies, padded off the size a
//! // signature keys on, with a hop limit of 12.
//! let profile = EvasionProfile::default()
//!     .with_source_port(53)
//!     .with_padding(24)
//!     .with_ttl(12);
//!
//! profile.validate()?;
//!
//! let mut cfg = ZondConfig::default();
//! cfg.evasion = profile;
//! # Ok::<(), zond_engine::evasion::EvasionError>(())
//! ```
//!
//! ## Some techniques cost a send path
//!
//! A raw socket cannot spoof a hardware address, spoof a source address for
//! decoys, or carry fragments the engine chose, because the kernel builds the
//! header. Setting any of these moves the scan to the link-layer path, which
//! cannot reach loopback or a tunnel.
//! [`EvasionProfile::effective_send_mode`] makes that choice and
//! [`requires_link_layer`](EvasionProfile::requires_link_layer) reports it.
//!
//! ## A profile shapes the probes
//!
//! The profile applies to every packet a scan sends to find a host or settle a
//! port's state, on whichever path sends it. A connect probe's socket carries it
//! for the life of the connection, so identification over that connection does
//! too. Later conversations on connections of their own leave with the
//! operating system's defaults: the service pass, the fingerprint engine's
//! second connections, TLS enumeration, detection exchanges, mDNS and SNMP
//! queries, and name lookups.
//!
//! The source port is why. A detection makes dozens of connections to one web
//! port, and with a fixed source port every one after the first would collide
//! with the previous connection, which stays in `TIME_WAIT` for up to four
//! minutes.

use std::net::IpAddr;

use crate::model::mac::MacAddr;
use crate::protocols::ip::SMALLEST_FRAGMENT_MTU;
use crate::protocols::sizes::{IP_V4_HDR_LEN, TCP_HDR_LEN};
use crate::transport::probe::Emission;
use crate::transport::probe::SendMode;

/// What a scan changes about the packets it sends, over the engine's defaults.
///
/// A default profile changes nothing. Set a field for each technique wanted;
/// [`is_active`](Self::is_active) reports whether any is set. Fields can be
/// assigned directly or through the chaining `with_` methods:
///
/// ```
/// use zond_engine::EvasionProfile;
///
/// let chained = EvasionProfile::default().with_source_port(53).with_ttl(12);
///
/// let mut assigned = EvasionProfile::default();
/// assigned.source_port = Some(53);
/// assigned.ttl = Some(12);
///
/// assert_eq!(chained, assigned);
/// assert!(chained.is_active());
/// ```
#[non_exhaustive]
#[must_use]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EvasionProfile {
    /// The source port every probe leaves from.
    ///
    /// Many stateless filters trust a source port: a rule that allows DNS
    /// replies allows anything from port 53, and one written for FTP data
    /// allows port 20.
    ///
    /// `None` keeps the engine's choice: a random high port per probe for raw
    /// TCP, one high port for the whole scan for UDP. Setting this pins both,
    /// and the connect scan's probes too.
    ///
    /// A connect probe's connection holds the port pair in `TIME_WAIT` after it
    /// closes. Rerunning the same scan straight away can't connect to that
    /// port; it is left unasked and the report names the held source port.
    pub source_port: Option<u16>,

    /// The hop limit (IPv4 TTL, IPv6 hop limit) written into every ordinary
    /// probe.
    ///
    /// For a filter or IDS that keys on hop count, or to make a probe expire at
    /// a chosen distance. `None` keeps
    /// [`HOP_LIMIT_ROUTED`](crate::protocols::ip::HOP_LIMIT_ROUTED).
    ///
    /// Traceroute ignores this: it varies the hop limit itself, one hop at a
    /// time, and that is the measurement.
    pub ttl: Option<u8>,

    /// How many random bytes to append to every probe's payload.
    ///
    /// A bare SYN is 40 bytes and an empty UDP probe 8, and a signature can key
    /// on exactly those sizes. The bytes are random because a run of zeroes is
    /// itself a fixed pattern. Applies to TCP and UDP probes.
    pub padding: Option<u16>,

    /// Whether every TCP probe carries a wrong checksum.
    ///
    /// A conformant host drops a segment whose checksum fails, so any reply
    /// came from something in the path that answered without checking: a
    /// firewall, an IPS, a load balancer. UDP probes are unaffected.
    pub bad_tcp_checksum: bool,

    /// The hardware address every frame claims to come from.
    ///
    /// For NAC and MAC-filtering tests. Only meaningful on the local segment,
    /// since a router rewrites the source address at the first hop. Requires
    /// the link-layer path (see [`effective_send_mode`](Self::effective_send_mode)),
    /// so a destination that path can't reach, such as loopback, is refused.
    pub spoof_mac: Option<MacAddr>,

    /// The largest size, in bytes, of each IP fragment a probe is split into.
    /// `None` sends probes whole.
    ///
    /// Hides the TCP header from filters and IDSs that only inspect whole
    /// headers. IPv4 fragments the header itself; IPv6 uses a fragment
    /// extension header, so its minimum is higher. Requires the link-layer path
    /// (see [`effective_send_mode`](Self::effective_send_mode)).
    pub fragment: Option<u16>,

    /// Source addresses to send a copy of every probe from, so an observer
    /// sees several scanners and can't tell which is real.
    ///
    /// The real probe goes out among its decoys in random order. Each decoy has
    /// a correct checksum for its own address, and replies to decoys are never
    /// recorded. Only decoys in the target's address family are used. Requires
    /// the link-layer path (see [`effective_send_mode`](Self::effective_send_mode)).
    /// Egress filtering usually drops spoofed packets, so decoys work best on
    /// the local segment.
    pub decoys: Vec<IpAddr>,

    /// The exact TCP flag byte every port probe carries, overriding the scan
    /// technique's own. Bits are those of [`crate::protocols::tcp::flags`].
    ///
    /// An arbitrary combination has no defined open/closed meaning, so ports
    /// probed with one are reported only as reachable or silent.
    ///
    /// Applies to the TCP port scan only. Host discovery, OS detection and
    /// firewall characterisation keep their own segments, because the segment's
    /// shape is part of what they measure.
    pub flags: Option<u8>,
}

/// The largest payload a probe can carry once its own headers are counted.
///
/// Taken from TCP over IPv4, the tightest case: IPv4's 16-bit length field
/// counts the headers too, while IPv6's counts only the payload.
const LARGEST_PAYLOAD: u16 = u16::MAX - (IP_V4_HDR_LEN + TCP_HDR_LEN) as u16;

/// Why a profile could not be honoured.
///
/// Covers only what the profile decides on its own. Problems that depend on
/// the destination, such as a fragment size below the IPv6 minimum, are
/// reported per probe.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum EvasionError {
    /// The fragment size cannot carry an IPv4 header and one unit of payload.
    ///
    /// A smaller fragment would carry no payload. See [`SMALLEST_FRAGMENT_MTU`].
    #[error(
        "a fragment size of {mtu} cannot carry a header and one eight-byte unit; {minimum} is the smallest that can"
    )]
    FragmentTooSmall {
        /// The size that was asked for.
        mtu: u16,
        /// The smallest that would work.
        minimum: u16,
    },

    /// A source port of zero. Replies would have nowhere to go, so every port
    /// would read as silent.
    #[error("a source port of zero is not one a probe can leave from")]
    SourcePortZero,

    /// The padding is larger than a probe carrying it could describe.
    #[error(
        "{padding} bytes of padding is more than a probe's length field can describe; {limit} is the most"
    )]
    PaddingTooLarge {
        /// The padding that was asked for.
        padding: u16,
        /// The most that would fit.
        limit: u16,
    },

    /// A hop limit of zero. The first router, or the local stack, drops every
    /// probe, and the scan would report a silent network.
    ///
    /// The packet itself builds and sends fine, so this is the only place the
    /// mistake is caught.
    #[error(
        "a hop limit of zero expires every probe before it leaves; 1 is the least that travels"
    )]
    HopLimitZero,
}

impl EvasionProfile {
    /// Checks what can be wrong with the profile itself: a fragment size too
    /// small to split to, a source port of zero, padding too large for a length
    /// field, and a hop limit of zero.
    ///
    /// Call it before a scan. Otherwise these show up only as a scan that sends
    /// nothing and reports a silent network. Whether the targets are reachable
    /// with this profile is decided per probe.
    ///
    /// ```
    /// use zond_engine::EvasionProfile;
    /// use zond_engine::evasion::EvasionError;
    ///
    /// // Twenty bytes can't hold an IPv4 header and a fragment.
    /// let refused = EvasionProfile::default().with_fragment(20);
    /// assert!(matches!(
    ///     refused.validate(),
    ///     Err(EvasionError::FragmentTooSmall { .. })
    /// ));
    ///
    /// assert!(EvasionProfile::default().with_fragment(576).validate().is_ok());
    /// ```
    ///
    /// # Errors
    ///
    /// The first [`EvasionError`] found.
    pub fn validate(&self) -> Result<(), EvasionError> {
        if let Some(mtu) = self.fragment
            && mtu < SMALLEST_FRAGMENT_MTU
        {
            return Err(EvasionError::FragmentTooSmall {
                mtu,
                minimum: SMALLEST_FRAGMENT_MTU,
            });
        }

        if self.source_port == Some(0) {
            return Err(EvasionError::SourcePortZero);
        }

        if let Some(padding) = self.padding
            && padding > LARGEST_PAYLOAD
        {
            return Err(EvasionError::PaddingTooLarge {
                padding,
                limit: LARGEST_PAYLOAD,
            });
        }

        if self.ttl == Some(0) {
            return Err(EvasionError::HopLimitZero);
        }

        Ok(())
    }

    /// Whether this profile changes anything: `false` for a default profile.
    #[must_use]
    pub fn is_active(&self) -> bool {
        *self != Self::default()
    }

    /// Whether this profile needs self-built Ethernet frames: it spoofs a
    /// hardware address, sets a fragment size, or uses decoys.
    #[must_use]
    pub fn requires_link_layer(&self) -> bool {
        self.spoof_mac.is_some() || self.fragment.is_some() || !self.decoys.is_empty()
    }

    /// The send mode a scan should actually open, given the one it asked for.
    ///
    /// [`SendMode::Auto`] becomes [`SendMode::Ethernet`] when the profile
    /// [requires the link layer](Self::requires_link_layer). An explicit mode
    /// is kept; if it can't carry the technique, each probe is refused.
    ///
    /// ```
    /// use zond_engine::EvasionProfile;
    /// use zond_engine::transport::probe::SendMode;
    ///
    /// let plain = EvasionProfile::default().with_ttl(64);
    /// assert_eq!(plain.effective_send_mode(SendMode::Auto), SendMode::Auto);
    ///
    /// let framed = EvasionProfile::default().with_fragment(576);
    /// assert_eq!(framed.effective_send_mode(SendMode::Auto), SendMode::Ethernet);
    ///
    /// // An explicit choice is kept.
    /// assert_eq!(
    ///     framed.effective_send_mode(SendMode::RawSocket),
    ///     SendMode::RawSocket
    /// );
    /// ```
    #[must_use]
    pub fn effective_send_mode(&self, requested: SendMode) -> SendMode {
        if self.requires_link_layer() && matches!(requested, SendMode::Auto) {
            SendMode::Ethernet
        } else {
            requested
        }
    }

    /// The [`source_port`] override if set, otherwise `default`.
    ///
    /// [`source_port`]: Self::source_port
    #[must_use]
    pub fn source_port_or(&self, default: u16) -> u16 {
        self.source_port.unwrap_or(default)
    }

    /// The [`Emission`] for an ordinary probe: the routed default with
    /// [`ttl`](Self::ttl), [`spoof_mac`](Self::spoof_mac) and
    /// [`fragment`](Self::fragment) applied where set.
    #[must_use]
    pub fn emission(&self) -> Emission {
        let mut emission = self.hop_limited_emission();
        emission.source_mac = self.spoof_mac;
        emission.fragment = self.fragment;
        emission
    }

    /// The emission with only the hop limit applied.
    ///
    /// Used by OS-detection probes, whose replies are the measurement: a
    /// spoofed or fragmented probe would change what the host answers.
    #[must_use]
    pub fn hop_limited_emission(&self) -> Emission {
        match self.ttl {
            Some(hop_limit) => Emission::routed().with_hop_limit(hop_limit),
            None => Emission::routed(),
        }
    }

    /// The [`padding`](Self::padding) and
    /// [`bad_tcp_checksum`](Self::bad_tcp_checksum) settings as one value.
    #[must_use]
    pub fn segment_shaping(&self) -> SegmentShaping {
        SegmentShaping {
            padding: self.padding,
            bad_tcp_checksum: self.bad_tcp_checksum,
        }
    }

    /// Sets the [source port](Self::source_port) every probe leaves from.
    pub fn with_source_port(mut self, port: u16) -> Self {
        self.source_port = Some(port);
        self
    }

    /// Sets the [hop limit](Self::ttl) every ordinary probe carries.
    pub fn with_ttl(mut self, ttl: u8) -> Self {
        self.ttl = Some(ttl);
        self
    }

    /// Sets the number of random [padding](Self::padding) bytes every probe
    /// appends to its payload.
    pub fn with_padding(mut self, padding: u16) -> Self {
        self.padding = Some(padding);
        self
    }

    /// Sets whether every TCP probe carries a
    /// [wrong checksum](Self::bad_tcp_checksum).
    pub fn with_bad_tcp_checksum(mut self, corrupt: bool) -> Self {
        self.bad_tcp_checksum = corrupt;
        self
    }

    /// Sets the [hardware address](Self::spoof_mac) every frame claims to come
    /// from.
    pub fn with_spoof_mac(mut self, mac: MacAddr) -> Self {
        self.spoof_mac = Some(mac);
        self
    }

    /// Sets the largest each [IP fragment](Self::fragment) a probe is split into
    /// may be, in bytes.
    pub fn with_fragment(mut self, mtu: u16) -> Self {
        self.fragment = Some(mtu);
        self
    }

    /// Sets the [decoy](Self::decoys) source addresses every probe is copied
    /// from.
    pub fn with_decoys(mut self, decoys: Vec<IpAddr>) -> Self {
        self.decoys = decoys;
        self
    }

    /// Sets the exact [TCP flag byte](Self::flags) every port probe carries.
    pub fn with_flags(mut self, flags: u8) -> Self {
        self.flags = Some(flags);
        self
    }
}

/// The evasion settings that live in the TCP or UDP segment. Produced by
/// [`EvasionProfile::segment_shaping`].
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SegmentShaping {
    /// See [`EvasionProfile::padding`].
    pub padding: Option<u16>,

    /// See [`EvasionProfile::bad_tcp_checksum`].
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
        // Otherwise an ordinary scan would report evasion it never used.
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
                .with_decoys(vec!["198.51.100.9".parse().unwrap()])
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
            .with_decoys(vec!["198.51.100.9".parse().unwrap()]);
        assert_eq!(profile.source_port, Some(53));
        assert_eq!(profile.ttl, Some(32));
        assert_eq!(profile.padding, Some(16));
        assert!(profile.bad_tcp_checksum);
        assert_eq!(profile.spoof_mac, Some(mac));
        assert_eq!(profile.fragment, Some(28));
        assert_eq!(
            profile.decoys,
            vec!["198.51.100.9".parse::<IpAddr>().unwrap()]
        );
    }

    #[test]
    fn source_port_resolves_to_the_override_when_set_and_the_default_otherwise() {
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
        assert_eq!(EvasionProfile::default().emission(), Emission::routed());
        assert_eq!(
            EvasionProfile::default().with_ttl(7).emission().hop_limit,
            7
        );
    }

    #[test]
    fn emission_carries_the_spoofed_hardware_address() {
        let mac = MacAddr::new(0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01);
        let emission = EvasionProfile::default().with_spoof_mac(mac).emission();
        assert_eq!(emission.source_mac, Some(mac));
        assert!(emission.requires_link_layer());

        let emission = EvasionProfile::default().with_fragment(28).emission();
        assert_eq!(emission.fragment, Some(28));
        assert!(emission.requires_link_layer());

        assert_eq!(EvasionProfile::default().emission().source_mac, None);
        assert_eq!(EvasionProfile::default().emission().fragment, None);
        assert!(!EvasionProfile::default().emission().requires_link_layer());
    }

    #[test]
    fn a_hop_limited_emission_carries_the_hop_limit_but_never_reshapes() {
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

    /// Each refusal, and the legal value next to it.
    #[test]
    fn validate_refuses_what_a_profile_alone_can_be_wrong_about() {
        let refused = |profile: EvasionProfile| profile.validate().expect_err("refused");

        assert_eq!(
            refused(EvasionProfile::default().with_fragment(SMALLEST_FRAGMENT_MTU - 1)),
            EvasionError::FragmentTooSmall {
                mtu: SMALLEST_FRAGMENT_MTU - 1,
                minimum: SMALLEST_FRAGMENT_MTU,
            }
        );
        assert_eq!(
            refused(EvasionProfile::default().with_source_port(0)),
            EvasionError::SourcePortZero
        );
        assert_eq!(
            refused(EvasionProfile::default().with_padding(u16::MAX)),
            EvasionError::PaddingTooLarge {
                padding: u16::MAX,
                limit: LARGEST_PAYLOAD,
            }
        );

        for allowed in [
            EvasionProfile::default().with_fragment(SMALLEST_FRAGMENT_MTU),
            EvasionProfile::default().with_source_port(1),
            EvasionProfile::default().with_padding(LARGEST_PAYLOAD),
        ] {
            assert_eq!(allowed.validate(), Ok(()), "{allowed:?}");
        }
        assert_eq!(
            refused(EvasionProfile::default().with_ttl(0)),
            EvasionError::HopLimitZero
        );
        assert!(
            EvasionProfile::default().with_ttl(1).validate().is_ok(),
            "one hop still travels, and expiring at a chosen distance is the point"
        );
    }

    /// `validate` and the fragmenter agree on the smallest fragment size.
    #[test]
    fn the_fragment_bound_is_the_one_the_fragmenter_refuses_at() {
        use crate::protocols::craft;
        use crate::protocols::error::PacketError;

        let header = craft::Ipv4::new(
            "192.0.2.1".parse().expect("literal"),
            "192.0.2.2".parse().expect("literal"),
        );
        // Larger than any MTU near the bound, so the datagram has to be split.
        let payload = vec![0u8; 40];

        assert!(
            matches!(
                crate::protocols::ip::fragment_ipv4(&header, &payload, SMALLEST_FRAGMENT_MTU - 1),
                Err(PacketError::MtuTooSmall { .. })
            ),
            "one below the published bound is refused"
        );
        assert!(
            crate::protocols::ip::fragment_ipv4(&header, &payload, SMALLEST_FRAGMENT_MTU).is_ok(),
            "and the bound itself is not"
        );
    }

    /// `validate` doesn't panic on any builder setting.
    #[test]
    fn every_builder_setting_validates_or_refuses_without_panicking() {
        let mac = MacAddr::new(0x02, 0, 0, 0, 0, 1);
        let decoy: IpAddr = "192.0.2.9".parse().expect("literal");

        for profile in [
            EvasionProfile::default(),
            EvasionProfile::default().with_source_port(u16::MAX),
            EvasionProfile::default().with_ttl(0),
            EvasionProfile::default().with_ttl(u8::MAX),
            EvasionProfile::default().with_padding(0),
            EvasionProfile::default().with_bad_tcp_checksum(true),
            EvasionProfile::default().with_spoof_mac(mac),
            EvasionProfile::default().with_fragment(u16::MAX),
            EvasionProfile::default().with_decoys(vec![decoy]),
            EvasionProfile::default().with_flags(0),
            EvasionProfile::default().with_flags(u8::MAX),
        ] {
            let _ = profile.validate();
        }
    }

    #[test]
    fn auto_becomes_ethernet_only_when_a_framing_technique_is_set() {
        let plain = EvasionProfile::default();
        let framing = EvasionProfile::default().with_spoof_mac(MacAddr::new(2, 0, 0, 0, 0, 1));

        assert_eq!(
            framing.effective_send_mode(SendMode::Auto),
            SendMode::Ethernet
        );
        // An explicit choice is kept even when it can't carry the technique.
        assert_eq!(plain.effective_send_mode(SendMode::Auto), SendMode::Auto);
        assert_eq!(
            framing.effective_send_mode(SendMode::RawSocket),
            SendMode::RawSocket
        );
        assert_eq!(
            plain.effective_send_mode(SendMode::Ethernet),
            SendMode::Ethernet
        );

        assert_eq!(
            EvasionProfile::default()
                .with_fragment(28)
                .effective_send_mode(SendMode::Auto),
            SendMode::Ethernet
        );

        assert_eq!(
            EvasionProfile::default()
                .with_decoys(vec!["198.51.100.9".parse().unwrap()])
                .effective_send_mode(SendMode::Auto),
            SendMode::Ethernet
        );
    }

    #[test]
    fn segment_shaping_carries_the_overrides_and_nothing_by_default() {
        assert_eq!(
            EvasionProfile::default().segment_shaping(),
            SegmentShaping::default()
        );

        let shaping = EvasionProfile::default()
            .with_padding(16)
            .with_bad_tcp_checksum(true)
            .segment_shaping();
        assert_eq!(shaping.padding, Some(16));
        assert!(shaping.bad_tcp_checksum);
    }
}
