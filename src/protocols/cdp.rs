// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Cisco Discovery Protocol
//!
//! The same job [`lldp`](crate::protocols::lldp) does, from the vendor that did
//! it first, and still the only one speaking on a great many enterprise
//! networks. Cisco equipment runs CDP by default and LLDP only when somebody
//! turns it on, so a segment that looks silent to the standard is often loudly
//! announcing itself here.
//!
//! It carries one thing LLDP's base standard does not: the **native VLAN** of
//! the port, which is the VLAN untagged traffic lands in. LLDP moves that into
//! an organizationally-specific TLV that plenty of equipment omits.
//!
//! ## It is not an EtherType protocol
//!
//! This is the part that trips a reader written by analogy with LLDP. CDP uses
//! the original 802.3 framing, where the two bytes after the addresses are a
//! *length* rather than a protocol number, and the protocol is named further in
//! by an LLC/SNAP header. A reader matching on
//! [`Frame::ethertype`](crate::protocols::ethernet::Frame::ethertype) finds a
//! small integer that names nothing and concludes there is no CDP on the
//! network.
//!
//! The consequence for length is real too: an 802.3 frame is padded out to the
//! minimum frame size, so the payload has to be cut to the length the header
//! claims rather than read to the end of the buffer — otherwise the walk below
//! runs into the padding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet_base::MacAddr;

use crate::protocols::ethernet::Frame;

/// The group address Cisco equipment sends these to.
pub const GROUP_ADDRESS: MacAddr = MacAddr(0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC);

/// The LLC header introducing a SNAP-encapsulated protocol: both service access
/// points set to the SNAP value, with unnumbered information framing.
const LLC_SNAP: [u8; 3] = [0xAA, 0xAA, 0x03];

/// Cisco's organizationally-unique identifier, and the protocol number it
/// assigns CDP within it.
const SNAP_HEADER: [u8; 5] = [0x00, 0x00, 0x0C, 0x20, 0x00];

/// Version, time to live, and a two-byte checksum precede the records.
const CDP_HDR_LEN: usize = 4;

/// A record's own header: two bytes of type and two of length.
const RECORD_HDR_LEN: usize = 4;

/// How many records are read out of one announcement.
///
/// As with [`lldp`](crate::protocols::lldp), the walk is driven by lengths the
/// sender chose, so something other than the sender has to bound it. A real
/// announcement carries under a dozen.
const MAX_RECORDS: usize = 128;

// Record type numbers.
const RECORD_DEVICE_ID: u16 = 0x0001;
const RECORD_ADDRESSES: u16 = 0x0002;
const RECORD_PORT_ID: u16 = 0x0003;
const RECORD_CAPABILITIES: u16 = 0x0004;
const RECORD_SOFTWARE_VERSION: u16 = 0x0005;
const RECORD_PLATFORM: u16 = 0x0006;
const RECORD_NATIVE_VLAN: u16 = 0x000A;
const RECORD_DUPLEX: u16 = 0x000B;
const RECORD_MANAGEMENT_ADDRESSES: u16 = 0x0016;

/// The protocol type byte marking a network-layer protocol identifier, and the
/// identifiers themselves, within an address record.
const PROTOCOL_TYPE_NLPID: u8 = 1;
const NLPID_IPV4: u8 = 0xCC;
const PROTOCOL_TYPE_IEEE_802_2: u8 = 2;

/// What a device says it does.
///
/// Unlike [`lldp::Capabilities`](crate::protocols::lldp::Capabilities) there is
/// only one set of bits here: CDP has no notion of a capability that is present
/// but switched off, so every bit set is a claim about behaviour.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities(u32);

impl Capabilities {
    const ROUTER: u32 = 0x01;
    const TRANSPARENT_BRIDGE: u32 = 0x02;
    const SOURCE_ROUTE_BRIDGE: u32 = 0x04;
    const SWITCH: u32 = 0x08;
    const HOST: u32 = 0x10;
    const IGMP: u32 = 0x20;
    const REPEATER: u32 = 0x40;

    /// Whether the device routes.
    pub fn is_router(self) -> bool {
        self.0 & Self::ROUTER != 0
    }

    /// Whether the device switches frames, by either of the two spellings CDP
    /// has for it.
    ///
    /// Cisco distinguishes a transparent bridge, a source-route bridge and a
    /// switch, which were three different products and are one answer to the
    /// question a reader is asking.
    pub fn is_switch(self) -> bool {
        self.0 & (Self::SWITCH | Self::TRANSPARENT_BRIDGE | Self::SOURCE_ROUTE_BRIDGE) != 0
    }

    /// Whether the device says it is an endpoint.
    pub fn is_host(self) -> bool {
        self.0 & Self::HOST != 0
    }

    /// Whether the device forwards at the physical layer.
    pub fn is_repeater(self) -> bool {
        self.0 & Self::REPEATER != 0
    }

    /// Whether the device says it snoops IGMP rather than flooding multicast.
    pub fn is_igmp_capable(self) -> bool {
        self.0 & Self::IGMP != 0
    }

    /// The raw bits, for a caller wanting one this type has no predicate for.
    pub fn bits(self) -> u32 {
        self.0
    }
}

/// One device's announcement of itself.
///
/// Every field is optional: CDP mandates nothing, and what a given platform
/// sends varies by model and by software version. A field that is `None` was not
/// sent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Announcement<'a> {
    /// What the device calls itself, which on Cisco equipment is the configured
    /// hostname and often the fully-qualified name.
    pub device_id: Option<&'a str>,

    /// What the device calls the port this frame left by — the port this
    /// machine is plugged into.
    pub port_id: Option<&'a str>,

    /// What the device says it does. See [`Capabilities`].
    pub capabilities: Option<Capabilities>,

    /// The software the device is running, as a banner: version, image name and
    /// build date, in a format that changes between releases.
    pub software_version: Option<&'a str>,

    /// The hardware model, as the vendor names it.
    pub platform: Option<&'a str>,

    /// The VLAN untagged traffic on this port lands in.
    ///
    /// The field this protocol is worth reading for even where LLDP is also
    /// running: LLDP carries the same fact only in an organizationally-specific
    /// TLV, which a great deal of equipment does not send.
    pub native_vlan: Option<u16>,

    /// Whether the port is running full duplex, where the device said.
    pub full_duplex: Option<bool>,

    /// An address the device is reachable at, where it advertised one.
    ///
    /// The first, from either the address record or the management-address
    /// record. As with LLDP, the question this answers is how to reach the box,
    /// and the first address answers it.
    pub address: Option<IpAddr>,
}

/// Reads `frame` as a CDP announcement, or `None` if it is not one.
///
/// # What identifies one
///
/// The LLC/SNAP header, which names Cisco's OUI and CDP's protocol number
/// within it. The destination address is deliberately *not* required to be
/// [`GROUP_ADDRESS`]: a frame captured on a mirrored port is addressed to
/// whoever the switch was talking to, and the SNAP header already says what the
/// frame is.
///
/// Individual records that cannot be read are skipped and the walk carries on,
/// for the reason [`lldp::parse`](crate::protocols::lldp::parse) gives: one
/// unreadable field should not cost the switch name beside it.
pub fn parse<'a>(frame: &Frame<'a>) -> Option<Announcement<'a>> {
    // Cut to the claimed length before anything else. An 802.3 frame is padded
    // to the minimum frame size, and the padding parses as records of type zero
    // and length zero — which is not a record, and would otherwise be walked
    // until the record bound stopped it.
    let payload = frame.payload_as_claimed()?;

    let (llc, rest) = payload.split_at_checked(LLC_SNAP.len())?;
    if llc != LLC_SNAP {
        return None;
    }

    let (snap, rest) = rest.split_at_checked(SNAP_HEADER.len())?;
    if snap != SNAP_HEADER {
        return None;
    }

    let mut rest = rest.get(CDP_HDR_LEN..)?;
    let mut announcement = Announcement::default();
    let mut seen = 0usize;

    while seen < MAX_RECORDS {
        let Some((kind, value, remainder)) = next_record(rest) else {
            break;
        };
        rest = remainder;
        seen += 1;

        match kind {
            RECORD_DEVICE_ID => announcement.device_id = text(value),
            RECORD_PORT_ID => announcement.port_id = text(value),
            RECORD_SOFTWARE_VERSION => announcement.software_version = text(value),
            RECORD_PLATFORM => announcement.platform = text(value),
            RECORD_CAPABILITIES => {
                announcement.capabilities = value
                    .first_chunk::<4>()
                    .map(|bytes| Capabilities(u32::from_be_bytes(*bytes)));
            }
            RECORD_NATIVE_VLAN => {
                announcement.native_vlan = value
                    .first_chunk::<2>()
                    .map(|bytes| u16::from_be_bytes(*bytes));
            }
            RECORD_DUPLEX => {
                announcement.full_duplex = value.first().map(|byte| *byte != 0);
            }
            RECORD_ADDRESSES | RECORD_MANAGEMENT_ADDRESSES => {
                announcement.address = announcement.address.or_else(|| first_address(value));
            }
            _ => {}
        }
    }

    // As with LLDP: bytes that arrived under CDP's SNAP header and named
    // nothing are not an announcement, and crediting a device with an empty one
    // would put a finding on the record that nothing said.
    let read_something = announcement.device_id.is_some()
        || announcement.port_id.is_some()
        || announcement.capabilities.is_some();

    read_something.then_some(announcement)
}

/// Splits one record off the front of `bytes`.
///
/// **The length counts the record's own header**, unlike LLDP's, which counts
/// only the value. A reader that treats it as a value length walks four bytes
/// short per record and desynchronises after the first one.
fn next_record(bytes: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let header = bytes.first_chunk::<4>()?;
    let kind = u16::from_be_bytes([header[0], header[1]]);
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));

    // A record shorter than its own header describes nothing, and taken at face
    // value would advance the walk by zero bytes for ever.
    if length < RECORD_HDR_LEN {
        return None;
    }

    let value = bytes.get(RECORD_HDR_LEN..length)?;
    let remainder = bytes.get(length..)?;

    Some((kind, value, remainder))
}

/// Reads the first address out of an address record.
///
/// The record is a count followed by that many entries, each naming the protocol
/// it belongs to before the address itself. Only the first entry is read: the
/// question is how to reach the device, and any of them answers it.
fn first_address(value: &[u8]) -> Option<IpAddr> {
    // A four-byte count of entries, then the entries.
    let rest = value.get(4..)?;

    let (protocol_type, rest) = rest.split_first()?;
    let (protocol_length, rest) = rest.split_first()?;
    let (protocol, rest) = rest.split_at_checked(usize::from(*protocol_length))?;

    let address_length = usize::from(u16::from_be_bytes(*rest.first_chunk::<2>()?));
    let address = rest.get(2..2 + address_length)?;

    match (*protocol_type, protocol) {
        // IPv4, named by its network-layer protocol identifier.
        (PROTOCOL_TYPE_NLPID, [NLPID_IPV4]) => address
            .first_chunk::<4>()
            .map(|bytes| IpAddr::V4(Ipv4Addr::from(*bytes))),
        // IPv6, named by the 802.2 encapsulation's own eight-byte identifier.
        // The address length is what actually settles it, and it is checked
        // rather than the identifier decoded.
        (PROTOCOL_TYPE_IEEE_802_2, _) if address_length == 16 => address
            .first_chunk::<16>()
            .map(|bytes| IpAddr::V6(Ipv6Addr::from(*bytes))),
        _ => None,
    }
}

/// Reads a record value as text, trimming a trailing NUL.
///
/// `None` for bytes that are not UTF-8, on the same reasoning as every other
/// reader in this module: a device that sends something else has produced
/// something to decline rather than to render with replacement characters.
fn text(value: &[u8]) -> Option<&str> {
    let trimmed = value.strip_suffix(&[0]).unwrap_or(value);
    if trimmed.is_empty() {
        return None;
    }
    std::str::from_utf8(trimmed).ok()
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
pub(crate) mod tests {
    use super::*;
    use crate::protocols::ethernet;

    pub(crate) const SWITCH_MAC: MacAddr = MacAddr(0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F);

    /// One record: two bytes of type, two of length, then the value — where the
    /// length **includes** those four bytes.
    fn record(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = u16::try_from(RECORD_HDR_LEN + value.len()).expect("a record length");
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    /// A CDP frame carrying `records`, framed as 802.3 with an LLC/SNAP header
    /// and padded to the minimum frame size the way a real one is.
    fn frame_of(records: &[Vec<u8>]) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&LLC_SNAP);
        payload.extend_from_slice(&SNAP_HEADER);
        // Version 2, 180-second hold time, and a checksum this does not verify.
        payload.extend_from_slice(&[0x02, 0xB4, 0x00, 0x00]);
        for record in records {
            payload.extend_from_slice(record);
        }

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[
            GROUP_ADDRESS.0,
            GROUP_ADDRESS.1,
            GROUP_ADDRESS.2,
            GROUP_ADDRESS.3,
            GROUP_ADDRESS.4,
            GROUP_ADDRESS.5,
        ]);
        bytes.extend_from_slice(&[
            SWITCH_MAC.0,
            SWITCH_MAC.1,
            SWITCH_MAC.2,
            SWITCH_MAC.3,
            SWITCH_MAC.4,
            SWITCH_MAC.5,
        ]);
        // 802.3: the field is the payload's length, not a protocol number.
        bytes.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("a length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&payload);

        // Padded to the minimum frame size, which is what makes cutting the
        // payload to its claimed length necessary rather than tidy.
        bytes.resize(bytes.len().max(60), 0);
        bytes
    }

    fn ipv4_address_record(address: Ipv4Addr) -> Vec<u8> {
        let mut value = 1u32.to_be_bytes().to_vec();
        value.push(PROTOCOL_TYPE_NLPID);
        value.push(1);
        value.push(NLPID_IPV4);
        value.extend_from_slice(&4u16.to_be_bytes());
        value.extend_from_slice(&address.octets());
        record(RECORD_ADDRESSES, &value)
    }

    /// A complete announcement from a Cisco switch that is also routing: named
    /// `core-sw-02`, on port `GigabitEthernet1/0/14`, untagged traffic in VLAN
    /// 40, reachable at `10.0.0.2`.
    ///
    /// The same four facts as
    /// [`lldp::tests::switch_announcement`](crate::protocols::lldp::tests::switch_announcement),
    /// deliberately, so the listener's tests can assert that both protocols
    /// arrive at one shape rather than assert twice against two.
    ///
    /// The device name is the bare one rather than the fully-qualified name a
    /// Cisco box usually sends, because what is under test there is that the
    /// field is carried across — not what the vendor puts in it.
    pub(crate) fn switch_announcement() -> Vec<u8> {
        frame_of(&[
            record(RECORD_DEVICE_ID, b"core-sw-02"),
            record(RECORD_PORT_ID, b"GigabitEthernet1/0/14"),
            record(
                RECORD_CAPABILITIES,
                &(Capabilities::SWITCH | Capabilities::ROUTER).to_be_bytes(),
            ),
            record(RECORD_NATIVE_VLAN, &40u16.to_be_bytes()),
            ipv4_address_record(Ipv4Addr::new(10, 0, 0, 2)),
        ])
    }

    /// The whole walk, over what a Cisco access switch actually sends.
    #[test]
    fn a_switch_announcement_is_read_field_by_field() {
        let bytes = frame_of(&[
            record(RECORD_DEVICE_ID, b"core-sw-02.example.net"),
            record(RECORD_PORT_ID, b"GigabitEthernet1/0/14"),
            record(
                RECORD_CAPABILITIES,
                &(Capabilities::SWITCH | Capabilities::IGMP).to_be_bytes(),
            ),
            record(RECORD_SOFTWARE_VERSION, b"Cisco IOS Software, Version 15.2"),
            record(RECORD_PLATFORM, b"cisco WS-C2960X-48TS-L"),
            record(RECORD_NATIVE_VLAN, &40u16.to_be_bytes()),
            record(RECORD_DUPLEX, &[1]),
            ipv4_address_record(Ipv4Addr::new(10, 0, 0, 2)),
        ]);

        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let announcement = parse(&frame).expect("a CDP announcement");

        assert_eq!(announcement.device_id, Some("core-sw-02.example.net"));
        assert_eq!(announcement.port_id, Some("GigabitEthernet1/0/14"));
        assert_eq!(
            announcement.software_version,
            Some("Cisco IOS Software, Version 15.2")
        );
        assert_eq!(announcement.platform, Some("cisco WS-C2960X-48TS-L"));
        assert_eq!(announcement.native_vlan, Some(40));
        assert_eq!(announcement.full_duplex, Some(true));
        assert_eq!(
            announcement.address,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );

        let capabilities = announcement.capabilities.expect("capabilities");
        assert!(capabilities.is_switch());
        assert!(capabilities.is_igmp_capable());
        assert!(!capabilities.is_router());
        assert!(!capabilities.is_host());
    }

    /// CDP rides 802.3 framing, so the field a reader would take for an
    /// EtherType is a length. A reader matching on the EtherType finds a small
    /// integer naming no protocol, decides there is no CDP, and reports a silent
    /// segment on a network that is announcing itself continuously.
    #[test]
    fn the_frame_is_identified_by_its_snap_header_rather_than_an_ethertype() {
        let bytes = frame_of(&[record(RECORD_DEVICE_ID, b"sw-01")]);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        assert!(
            frame.payload_length().is_some(),
            "the field is a length, not an EtherType"
        );
        assert!(
            frame.ethertype().0 <= 1500,
            "and so it names no protocol: {:#06x}",
            frame.ethertype().0
        );
        assert_eq!(
            parse(&frame).expect("an announcement").device_id,
            Some("sw-01")
        );
    }

    /// An 802.3 frame is padded out to the minimum frame size. Read to the end
    /// of the buffer, the walk runs into that padding — which decodes as records
    /// of type zero and length zero, and a length of zero advances the walk by
    /// nothing at all.
    #[test]
    fn trailing_padding_is_cut_off_rather_than_walked() {
        // One short record, so the frame is padded well past the real content.
        let bytes = frame_of(&[record(RECORD_DEVICE_ID, b"sw")]);
        assert_eq!(bytes.len(), 60, "the fixture is padded, as a real frame is");

        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let announcement = parse(&frame).expect("it returns rather than hanging");

        assert_eq!(announcement.device_id, Some("sw"));
        assert_eq!(announcement.port_id, None, "the padding invented nothing");
    }

    /// A CDP record's length counts its own four-byte header, where LLDP's
    /// counts only the value. Read with LLDP's rule, the walk lands four bytes
    /// short after the first record and every field after it is nonsense.
    #[test]
    fn a_record_length_counts_its_own_header() {
        let bytes = frame_of(&[
            record(RECORD_DEVICE_ID, b"sw-01"),
            record(RECORD_PORT_ID, b"Gi1/0/1"),
            record(RECORD_NATIVE_VLAN, &99u16.to_be_bytes()),
        ]);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let announcement = parse(&frame).expect("an announcement");

        assert_eq!(announcement.device_id, Some("sw-01"));
        assert_eq!(
            announcement.port_id,
            Some("Gi1/0/1"),
            "the second record was found where the first said it would be"
        );
        assert_eq!(announcement.native_vlan, Some(99), "and so was the third");
    }

    /// A record claiming a length of zero would advance the walk by nothing.
    /// Left to the record bound alone that is a hundred and twenty-eight wasted
    /// iterations per frame; taken at face value with no bound at all it never
    /// returns.
    #[test]
    fn a_record_shorter_than_its_own_header_stops_the_walk() {
        let mut bytes = frame_of(&[record(RECORD_DEVICE_ID, b"sw-01")]);
        // Append a record claiming length zero, then plenty behind it.
        let insert_at = bytes.len() - 20;
        bytes.splice(
            insert_at..insert_at,
            [0x00, 0x03, 0x00, 0x00].into_iter().chain([0u8; 8]),
        );

        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let announcement = parse(&frame).expect("it returns rather than hanging");

        assert_eq!(announcement.device_id, Some("sw-01"));
    }

    /// An ordinary IP frame is not an announcement, which is nearly everything
    /// on any capture wide enough to see one.
    #[test]
    fn a_frame_of_another_protocol_is_declined() {
        let bytes = ethernet::build_header(
            SWITCH_MAC,
            GROUP_ADDRESS,
            pnet_packet::ethernet::EtherTypes::Ipv4,
        );
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        assert_eq!(parse(&frame), None);
    }

    /// An 802.3 frame carrying some other SNAP protocol is not one either.
    #[test]
    fn another_snap_protocol_is_declined() {
        let mut bytes = frame_of(&[record(RECORD_DEVICE_ID, b"sw-01")]);
        // Change the SNAP protocol number, leaving Cisco's OUI in place.
        let snap_protocol_at = 14 + LLC_SNAP.len() + 3;
        bytes[snap_protocol_at] = 0x01;
        bytes[snap_protocol_at + 1] = 0x11;

        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        assert_eq!(parse(&frame), None);
    }
}
