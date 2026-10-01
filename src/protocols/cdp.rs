// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Cisco Discovery Protocol
//!
//! The same job as [`lldp`](crate::protocols::lldp), and the only one spoken on
//! many enterprise networks: Cisco equipment runs CDP by default and LLDP only
//! when configured, so a segment silent to LLDP is often announcing itself here.
//!
//! CDP also carries the port's **native VLAN** (where untagged traffic lands),
//! which LLDP moves into an organizationally-specific TLV that plenty of
//! equipment omits.
//!
//! ## Not an EtherType protocol
//!
//! CDP uses 802.3 framing: the two bytes after the addresses are a *length*,
//! and the protocol is named further in by an LLC/SNAP header. A reader
//! matching on [`Frame::ethertype`](crate::protocols::ethernet::Frame::ethertype)
//! finds a small integer that names nothing.
//!
//! An 802.3 frame is also padded to the minimum frame size, so the payload must
//! be cut to the length the header claims or the walk runs into the padding.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::model::mac::MacAddr;

use crate::protocols::ethernet::Frame;
use crate::protocols::text::field as text;

/// The group address Cisco equipment sends these to.
pub const GROUP_ADDRESS: MacAddr = MacAddr::new(0x01, 0x00, 0x0C, 0xCC, 0xCC, 0xCC);

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
/// The walk is driven by lengths the sender chose, so it is bounded here. A
/// real announcement carries under a dozen.
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
/// one set of bits: CDP has no notion of a capability present but disabled, so
/// every bit set is a claim about behaviour.
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

    /// Whether the device switches frames. Cisco's transparent-bridge,
    /// source-route-bridge and switch bits all count.
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

    /// Whether the device says it snoops IGMP instead of flooding multicast.
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
/// Every field is optional: CDP mandates nothing, and what a platform sends
/// varies by model and software version. `None` means not sent.
///
/// `#[non_exhaustive]`: these are nine of the record types Cisco equipment
/// sends, and more may be read.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Announcement<'a> {
    /// What the device calls itself: on Cisco equipment the configured hostname,
    /// often fully qualified.
    pub device_id: Option<&'a str>,

    /// What the device calls the port this frame left by, which is the port this
    /// machine is plugged into.
    pub port_id: Option<&'a str>,

    /// What the device says it does. See [`Capabilities`].
    pub capabilities: Option<Capabilities>,

    /// The software banner: version, image name and build date, in a format that
    /// changes between releases.
    pub software_version: Option<&'a str>,

    /// The hardware model, as the vendor names it.
    pub platform: Option<&'a str>,

    /// The VLAN untagged traffic on this port lands in.
    ///
    /// LLDP carries this only in an organizationally-specific TLV that much
    /// equipment does not send.
    pub native_vlan: Option<u16>,

    /// Whether the port is running full duplex, where the device said.
    pub full_duplex: Option<bool>,

    /// The first address the device advertised, from the address record or the
    /// management-address record.
    pub address: Option<IpAddr>,
}

/// Reads `frame` as a CDP announcement, or `None` if it is not one.
///
/// # What identifies one
///
/// The LLC/SNAP header naming Cisco's OUI and CDP's protocol number. The
/// destination need not be [`GROUP_ADDRESS`]: on a mirrored port a frame is
/// addressed to whoever the switch was talking to.
///
/// Records that cannot be read are skipped and the walk continues, as in
/// [`lldp::parse`](crate::protocols::lldp::parse).
pub fn parse<'a>(frame: &Frame<'a>) -> Option<Announcement<'a>> {
    // Cut to the claimed length first: the 802.3 padding parses as records of
    // type zero and length zero.
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

        // Every field keeps the first readable value, so a malformed repeat cannot
        // erase one that parsed (as in `lldp::parse`).
        match kind {
            RECORD_DEVICE_ID => keep_first(&mut announcement.device_id, text(value)),
            RECORD_PORT_ID => keep_first(&mut announcement.port_id, text(value)),
            RECORD_SOFTWARE_VERSION => keep_first(&mut announcement.software_version, text(value)),
            RECORD_PLATFORM => keep_first(&mut announcement.platform, text(value)),
            RECORD_CAPABILITIES => keep_first(
                &mut announcement.capabilities,
                value
                    .first_chunk::<4>()
                    .map(|bytes| Capabilities(u32::from_be_bytes(*bytes))),
            ),
            RECORD_NATIVE_VLAN => keep_first(
                &mut announcement.native_vlan,
                value
                    .first_chunk::<2>()
                    .map(|bytes| u16::from_be_bytes(*bytes)),
            ),
            RECORD_DUPLEX => keep_first(
                &mut announcement.full_duplex,
                value.first().map(|byte| *byte != 0),
            ),
            RECORD_ADDRESSES | RECORD_MANAGEMENT_ADDRESSES => {
                keep_first(&mut announcement.address, first_address(value));
            }
            _ => {}
        }
    }

    // Bytes under CDP's SNAP header that named nothing are not an announcement.
    let read_something = announcement.device_id.is_some()
        || announcement.port_id.is_some()
        || announcement.capabilities.is_some();

    read_something.then_some(announcement)
}

/// Records `value` in `field` if the field is still empty and the value is
/// readable.
///
/// As in [`lldp`](crate::protocols::lldp): a longer prefix of an announcement
/// reports everything a shorter one did.
fn keep_first<T>(field: &mut Option<T>, value: Option<T>) {
    if field.is_none() {
        *field = value;
    }
}

/// Splits one record off the front of `bytes`.
///
/// The length counts the record's own header, unlike LLDP's. Read as a value
/// length, the walk falls four bytes short per record.
fn next_record(bytes: &[u8]) -> Option<(u16, &[u8], &[u8])> {
    let header = bytes.first_chunk::<4>()?;
    let kind = u16::from_be_bytes([header[0], header[1]]);
    let length = usize::from(u16::from_be_bytes([header[2], header[3]]));

    // A record shorter than its own header would advance the walk by zero bytes
    // forever.
    if length < RECORD_HDR_LEN {
        return None;
    }

    let value = bytes.get(RECORD_HDR_LEN..length)?;
    let remainder = bytes.get(length..)?;

    Some((kind, value, remainder))
}

/// Reads the first address out of an address record.
///
/// The record is a count followed by entries, each naming its protocol before
/// the address. Only the first entry is read.
fn first_address(value: &[u8]) -> Option<IpAddr> {
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
        // IPv6, named by the 802.2 encapsulation's eight-byte identifier. The
        // address length settles it.
        (PROTOCOL_TYPE_IEEE_802_2, _) if address_length == 16 => address
            .first_chunk::<16>()
            .map(|bytes| IpAddr::V6(Ipv6Addr::from(*bytes))),
        _ => None,
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
pub(crate) mod tests {
    use super::*;
    use crate::protocols::ethernet;

    pub(crate) const SWITCH_MAC: MacAddr = MacAddr::new(0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F);

    /// One record: two bytes of type, two of length, then the value, where the
    /// length includes those four bytes.
    fn record(kind: u16, value: &[u8]) -> Vec<u8> {
        let length = u16::try_from(RECORD_HDR_LEN + value.len()).expect("a record length");
        let mut bytes = kind.to_be_bytes().to_vec();
        bytes.extend_from_slice(&length.to_be_bytes());
        bytes.extend_from_slice(value);
        bytes
    }

    /// A CDP frame carrying `records`: 802.3 with an LLC/SNAP header, padded to
    /// the minimum frame size as a real one is.
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
        bytes.extend_from_slice(&GROUP_ADDRESS.octets());
        bytes.extend_from_slice(&SWITCH_MAC.octets());
        // 802.3: the field is the payload's length, not a protocol number.
        bytes.extend_from_slice(
            &u16::try_from(payload.len())
                .expect("a length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(&payload);

        // Padded to the minimum frame size, which is why the payload must be cut.
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

    /// A second record of a kind an announcement carries once does not erase
    /// the first, even when it is unreadable. The fuzz target holds the same
    /// property over LLDP.
    #[test]
    fn a_second_unreadable_record_does_not_erase_the_first() {
        let bytes = frame_of(&[
            record(RECORD_DEVICE_ID, b"core-switch-01"),
            record(RECORD_DEVICE_ID, &[0xFF, 0xFE, 0xFD]),
            record(RECORD_PORT_ID, b"GigabitEthernet1/0/14"),
        ]);
        let frame = ethernet::parse(&bytes).expect("a frame");
        let announcement = parse(&frame).expect("an announcement");

        assert_eq!(announcement.device_id, Some("core-switch-01"));
        assert_eq!(announcement.port_id, Some("GigabitEthernet1/0/14"));
    }

    /// A complete announcement from a Cisco switch that is also routing: named
    /// `core-sw-02`, on port `GigabitEthernet1/0/14`, untagged traffic in VLAN
    /// 40, reachable at `198.51.100.2`.
    ///
    /// The same four facts as
    /// [`lldp::tests::switch_announcement`](crate::protocols::lldp::tests::switch_announcement),
    /// so the listener's tests can assert both protocols arrive at one shape.
    /// The device name is the bare one, since the test is about the field being
    /// carried across.
    pub(crate) fn switch_announcement() -> Vec<u8> {
        frame_of(&[
            record(RECORD_DEVICE_ID, b"core-sw-02"),
            record(RECORD_PORT_ID, b"GigabitEthernet1/0/14"),
            record(
                RECORD_CAPABILITIES,
                &(Capabilities::SWITCH | Capabilities::ROUTER).to_be_bytes(),
            ),
            record(RECORD_NATIVE_VLAN, &40u16.to_be_bytes()),
            ipv4_address_record(Ipv4Addr::new(198, 51, 100, 2)),
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
            ipv4_address_record(Ipv4Addr::new(198, 51, 100, 2)),
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
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)))
        );

        let capabilities = announcement.capabilities.expect("capabilities");
        assert!(capabilities.is_switch());
        assert!(capabilities.is_igmp_capable());
        assert!(!capabilities.is_router());
        assert!(!capabilities.is_host());
    }

    /// CDP rides 802.3 framing, so the field a reader would take for an
    /// EtherType is a length.
    #[test]
    fn the_frame_is_identified_by_its_snap_header_rather_than_an_ethertype() {
        let bytes = frame_of(&[record(RECORD_DEVICE_ID, b"sw-01")]);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        assert!(
            frame.payload_length().is_some(),
            "the field is a length, not an EtherType"
        );
        assert!(
            frame.ethertype() <= 1500,
            "and so it names no protocol: {:#06x}",
            frame.ethertype()
        );
        assert_eq!(
            parse(&frame).expect("an announcement").device_id,
            Some("sw-01")
        );
    }

    /// The 802.3 padding decodes as zero-length records of type zero and must
    /// not be walked.
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

    /// A CDP record's length counts its own four-byte header, unlike LLDP's.
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

    /// A record claiming a length of zero would advance the walk by nothing,
    /// forever without the record bound.
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

    /// An ordinary IP frame is not an announcement.
    #[test]
    fn a_frame_of_another_protocol_is_declined() {
        let bytes = ethernet::build_header(
            SWITCH_MAC,
            GROUP_ADDRESS,
            pnet_packet::ethernet::EtherTypes::Ipv4.0,
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
