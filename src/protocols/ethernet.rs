// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Ethernet framing
//!
//! The outermost header on everything the link-layer paths send, and the first
//! thing read off everything they capture. Building one cannot fail (fourteen
//! bytes, no options, no VLAN tag); reading one can.
//!
//! ## VLAN tags
//!
//! An 802.1Q tag sits between the addresses and the EtherType and pushes the
//! EtherType four bytes along. A reader taking it from the usual offset reads
//! `0x8100` on a tagged frame and declines it, so a scan on a trunk port would
//! report an empty segment.
//!
//! [`Frame`] walks the tags once, keeps them, and answers
//! [`ethertype`](Frame::ethertype) and [`payload`](Frame::payload) with what is
//! behind them, so readers built on it are VLAN-transparent. The tags stay
//! readable, which on a trunk is a finding of its own.

use crate::model::mac::MacAddr;

use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::ETH_HDR_LEN;

/// The width of one 802.1Q tag: the tag protocol identifier that announced it,
/// and the two bytes of tag control information.
pub const VLAN_TAG_LEN: usize = 4;

/// How many stacked VLAN tags a frame is read through.
///
/// Two covers a plain 802.1Q tag and one layer of QinQ (a customer tag inside
/// a provider tag, as a carrier hands off).
///
/// Each tag's protocol identifier comes off the wire, so without a bound a
/// frame made of nothing but tags would decide how long the walk runs. A frame
/// with more tags is read as carrying an unrecognised EtherType and declined.
pub const MAX_VLAN_TAGS: usize = 2;

/// The largest payload an 802.3 frame may claim, and so the boundary that tells
/// a length field from an EtherType.
///
/// EtherType values start at 1536, above this, so one field can carry either.
/// See [`Frame::payload_length`].
const MAX_PAYLOAD_LEN: u16 = 1500;

/// Tag protocol identifiers that introduce a VLAN tag.
///
/// `0x8100` is the 802.1Q customer tag. `0x88A8` is the 802.1ad service tag a
/// provider adds outside it, and `0x9100` is the pre-standard spelling, still
/// emitted by older equipment.
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88A8, 0x9100];

/// One 802.1Q tag, as it appeared on the wire.
///
/// Which VLANs a link carries is something no probe can ask for, and on a
/// trunk port it is most of what there is to learn about the network behind
/// the switch.
///
/// Not `#[non_exhaustive]`: 802.1Q spends every bit of the 16-bit tag control
/// information (three priority, one drop-eligible, twelve identifier), so a
/// caller may build one and match it exhaustively.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VlanTag {
    /// The tag protocol identifier that introduced this tag: customer or provider.
    pub protocol: u16,
    /// The VLAN identifier, twelve bits.
    pub id: u16,
    /// The priority code point, three bits: which traffic class the sender put
    /// this frame in.
    pub priority: u8,
    /// The drop-eligible indicator, one bit. Set on a frame the sender is
    /// content to have discarded first under congestion.
    pub drop_eligible: bool,
}

impl VlanTag {
    /// Reads the two bytes of tag control information following `protocol`.
    fn read(protocol: u16, tci: [u8; 2]) -> Self {
        let tci = u16::from_be_bytes(tci);
        Self {
            protocol,
            id: tci & 0x0FFF,
            priority: (tci >> 13) as u8,
            drop_eligible: tci & 0x1000 != 0,
        }
    }
}

/// An Ethernet frame, walked past any VLAN tags to whatever it actually
/// carries.
///
/// The type every reader of a captured frame takes. It borrows the bytes, so
/// [`payload`](Self::payload) returns a slice borrowed from the frame, not the
/// view, and a parsed header can outlive the walk that found it.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    bytes: &'a [u8],
    /// Everything past the header and any tags.
    ///
    /// Stored as a slice so reading it cannot be out of bounds.
    payload: &'a [u8],
    /// What the frame carries, read from behind the tags.
    ethertype: u16,
    tags: [VlanTag; MAX_VLAN_TAGS],
    depth: usize,
}

impl<'a> Frame<'a> {
    /// The hardware address this frame was sent to.
    pub fn destination(&self) -> MacAddr {
        Self::mac_at(self.bytes, 0)
    }

    /// The hardware address this frame was sent from.
    ///
    /// On a segment this is the one field that says whether a frame came from the
    /// host it claims to: a host answering in another's place can use that host's
    /// IP address but not its hardware address.
    pub fn source(&self) -> MacAddr {
        Self::mac_at(self.bytes, 6)
    }

    /// What the frame carries, read from behind any VLAN tags.
    ///
    /// Never a tag protocol identifier for a frame that parsed.
    pub fn ethertype(&self) -> u16 {
        self.ethertype
    }

    /// The VLAN tags this frame arrived under, outermost first. Empty for the
    /// ordinary untagged case.
    pub fn vlans(&self) -> &[VlanTag] {
        &self.tags[..self.depth]
    }

    /// Everything after the header and the tags.
    ///
    /// Borrowed from the frame, so a header parsed out of it may outlive the
    /// [`Frame`] that located it.
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    /// The whole frame, tags and header included.
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// How many bytes of payload the header claims, for a frame using the
    /// original 802.3 framing.
    ///
    /// Ethernet II puts an EtherType in this field and 802.3 a length, told apart
    /// by magnitude: the largest legal payload is 1500 and the smallest assigned
    /// EtherType is 1536. Hence [`ethertype`](Self::ethertype) can be a number that
    /// names no protocol.
    ///
    /// 802.3 framing carries the LLC/SNAP protocols switches announce themselves
    /// over, and such a frame is padded to the minimum size, so the payload must
    /// be cut to this length.
    ///
    /// `None` for an Ethernet II frame.
    pub fn payload_length(&self) -> Option<usize> {
        (self.ethertype <= MAX_PAYLOAD_LEN).then_some(usize::from(self.ethertype))
    }

    /// The payload, cut to the length an 802.3 header claimed.
    ///
    /// The same as [`payload`](Self::payload) for an Ethernet II frame. `None`
    /// when the header claims more than arrived.
    pub fn payload_as_claimed(&self) -> Option<&'a [u8]> {
        match self.payload_length() {
            Some(length) => self.payload.get(..length),
            None => Some(self.payload),
        }
    }

    fn mac_at(bytes: &[u8], offset: usize) -> MacAddr {
        // `parse` has already refused anything shorter than a header, so both
        // address ranges are present.
        MacAddr::new(
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
            bytes[offset + 4],
            bytes[offset + 5],
        )
    }
}

/// Builds the Ethernet header carrying ethertype `et` from `src_mac` to
/// `dst_mac`.
pub fn build_header(src_mac: MacAddr, dst_mac: MacAddr, et: u16) -> Vec<u8> {
    craft::Ethernet::new(src_mac, dst_mac)
        .with_ethertype(et)
        .header_bytes()
}

/// Reads `frame_bytes` as an Ethernet frame, walking past any VLAN tags.
///
/// # Errors
///
/// [`PacketError::Truncated`] when there are too few bytes for the header or
/// the tags it claims. The reported size is what the walk had reached, so a
/// frame short of its second tag says so.
pub fn parse(frame_bytes: &'_ [u8]) -> Result<Frame<'_>> {
    let short_of = |needed| PacketError::truncated("an Ethernet frame", needed, frame_bytes.len());

    let mut ethertype = u16::from_be_bytes([
        *frame_bytes.get(12).ok_or_else(|| short_of(ETH_HDR_LEN))?,
        *frame_bytes.get(13).ok_or_else(|| short_of(ETH_HDR_LEN))?,
    ]);

    let mut payload_offset = ETH_HDR_LEN;
    let mut tags = [VlanTag {
        protocol: 0,
        id: 0,
        priority: 0,
        drop_eligible: false,
    }; MAX_VLAN_TAGS];
    let mut depth = 0;

    // Bounded: see `MAX_VLAN_TAGS`.
    while depth < MAX_VLAN_TAGS && VLAN_TPIDS.contains(&ethertype) {
        // A frame ending inside a tag is short of the header and the tag.
        let through_tag = payload_offset + VLAN_TAG_LEN;
        let tci = [
            *frame_bytes
                .get(payload_offset)
                .ok_or_else(|| short_of(through_tag))?,
            *frame_bytes
                .get(payload_offset + 1)
                .ok_or_else(|| short_of(through_tag))?,
        ];
        let inner = u16::from_be_bytes([
            *frame_bytes
                .get(payload_offset + 2)
                .ok_or_else(|| short_of(through_tag))?,
            *frame_bytes
                .get(payload_offset + 3)
                .ok_or_else(|| short_of(through_tag))?,
        ]);

        tags[depth] = VlanTag::read(ethertype, tci);
        depth += 1;
        payload_offset += VLAN_TAG_LEN;
        ethertype = inner;
    }

    Ok(Frame {
        bytes: frame_bytes,
        payload: frame_bytes
            .get(payload_offset..)
            .ok_or_else(|| short_of(payload_offset))?,
        ethertype,
        tags,
        depth,
    })
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
    use pnet_packet::ethernet::EtherTypes;

    const DST: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 1);
    const SRC: MacAddr = MacAddr::new(0x02, 0, 0, 0, 0, 2);

    /// A frame carrying `ethertype`, wrapped in `tags` from the outside in.
    ///
    /// Each entry is `(tag protocol, tag control information)`, so a test can
    /// build a customer tag inside a provider tag and say which is which.
    fn frame_with(tags: &[(u16, u16)], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DST.octets());
        bytes.extend_from_slice(&SRC.octets());

        // Each tag is its protocol identifier and two bytes of tag control
        // information; the next tag's protocol, or the real EtherType after the
        // last, says what follows.
        for (protocol, tci) in tags {
            bytes.extend_from_slice(&protocol.to_be_bytes());
            bytes.extend_from_slice(&tci.to_be_bytes());
        }

        bytes.extend_from_slice(&ethertype.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// A tagged frame reports the EtherType behind the tag, not `0x8100`.
    #[test]
    fn a_tagged_frame_reports_what_is_behind_the_tag() {
        let bytes = frame_with(&[(0x8100, 0x0064)], EtherTypes::Ipv4.0, &[0xAB; 20]);
        let frame = parse(&bytes).expect("a tagged frame parses");

        assert_eq!(frame.ethertype(), EtherTypes::Ipv4.0);
        assert_eq!(frame.payload(), &[0xAB; 20]);
        assert_eq!(frame.source(), SRC, "a tag does not move the addresses");
        assert_eq!(frame.destination(), DST);
    }

    /// The tag is kept and readable.
    #[test]
    fn the_tag_itself_is_kept() {
        // Priority 3, drop-eligible set, VLAN 100.
        let tci = (3 << 13) | 0x1000 | 100;
        let bytes = frame_with(&[(0x8100, tci)], EtherTypes::Ipv6.0, &[]);
        let frame = parse(&bytes).expect("a tagged frame parses");

        assert_eq!(
            frame.vlans(),
            &[VlanTag {
                protocol: 0x8100,
                id: 100,
                priority: 3,
                drop_eligible: true,
            }]
        );
    }

    /// A provider tag outside a customer tag, as a carrier hands off. Read
    /// through only the outer one, the frame would read as carrying `0x8100`.
    #[test]
    fn a_stacked_tag_is_walked_to_the_protocol_behind_both() {
        let bytes = frame_with(
            &[(0x88A8, 0x0FA0), (0x8100, 0x0064)],
            EtherTypes::Arp.0,
            &[0xCD; 28],
        );
        let frame = parse(&bytes).expect("a QinQ frame parses");

        assert_eq!(frame.ethertype(), EtherTypes::Arp.0);
        assert_eq!(frame.payload(), &[0xCD; 28]);
        assert_eq!(
            frame.vlans().iter().map(|tag| tag.id).collect::<Vec<_>>(),
            vec![4000, 100],
            "outermost first"
        );
    }

    /// A frame of nothing but tags terminates and is declined.
    #[test]
    fn a_frame_of_nothing_but_tags_terminates_and_is_declined() {
        let tags: Vec<(u16, u16)> = std::iter::repeat_n((0x8100, 1), 40).collect();
        let bytes = frame_with(&tags, 0x8100, &[0u8; 8]);

        let frame = parse(&bytes).expect("it parses rather than hanging");

        assert_eq!(frame.vlans().len(), MAX_VLAN_TAGS, "the walk stopped");
        assert_eq!(
            frame.ethertype(),
            0x8100,
            "and reports a tag protocol as the ethertype, which every reader declines"
        );
    }

    /// A capture truncated to its snapshot length can end inside a tag. The
    /// reported size is what the walk had reached, not the fixed header size.
    #[test]
    fn a_frame_ending_inside_a_tag_is_refused_rather_than_read_past() {
        let bytes = frame_with(&[(0x8100, 0x0064)], EtherTypes::Ipv4.0, &[]);

        for cut in ETH_HDR_LEN..bytes.len() {
            let refused = parse(&bytes[..cut]);
            let Err(PacketError::Truncated { needed, got, .. }) = refused else {
                panic!("a frame cut to {cut} bytes claims a tag it does not carry: {refused:?}");
            };
            assert_eq!(got, cut);
            assert!(
                needed > got,
                "a {got}-byte frame was refused for needing only {needed}"
            );
        }

        assert!(parse(&bytes).is_ok(), "the whole frame still parses");
    }

    /// The ordinary untagged case reads exactly as a plain Ethernet header.
    #[test]
    fn an_untagged_frame_reads_as_it_always_did() {
        let bytes = frame_with(&[], EtherTypes::Ipv4.0, &[0x11; 20]);
        let frame = parse(&bytes).expect("an untagged frame parses");

        assert_eq!(frame.ethertype(), EtherTypes::Ipv4.0);
        assert_eq!(frame.payload(), &[0x11; 20]);
        assert!(frame.vlans().is_empty());
    }
}
