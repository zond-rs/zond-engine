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
//! thing read off everything they capture.
//!
//! Building one cannot fail: fourteen bytes with no options and no VLAN tag, so
//! the buffer is exactly the header written into it. Reading one can, because
//! the bytes come off the wire and a wire carries whatever it likes.
//!
//! ## What a tag does to a reader that has not heard of one
//!
//! An 802.1Q tag sits between the addresses and the EtherType and pushes the
//! EtherType four bytes further along. A reader taking the EtherType from its
//! usual offset therefore reads `0x8100` on a tagged frame — not IPv4, not IPv6,
//! not ARP — and declines it. Every such frame is then invisible, and invisible
//! in the way that is hardest to notice: a scan on a trunk port finds nothing
//! and reports an empty segment.
//!
//! [`Frame`] is the answer, and it is why reading a frame goes through a view
//! rather than through `pnet`'s [`EthernetPacket`] directly. It walks the tags
//! once, keeps them, and answers [`ethertype`](Frame::ethertype) and
//! [`payload`](Frame::payload) with what is *behind* them. A reader written
//! against it is VLAN-transparent without knowing that VLANs exist, and the tags
//! stay readable for anything that wants them — which on a trunk is a finding in
//! its own right.

use pnet::datalink::MacAddr;
use pnet::packet::ethernet::EtherType;

use crate::protocols::craft;
use crate::protocols::error::{PacketError, Result};
use crate::protocols::sizes::ETH_HDR_LEN;

/// The width of one 802.1Q tag: the tag protocol identifier that announced it,
/// and the two bytes of tag control information.
pub const VLAN_TAG_LEN: usize = 4;

/// How many stacked VLAN tags a frame is read through.
///
/// Two, which covers a plain 802.1Q tag and one layer of QinQ — a customer tag
/// inside a provider tag, which is what a carrier hands off. Three is not a
/// thing this engine has ever been shown.
///
/// **The bound is the point, not the number.** The tag stack is walked by
/// following each tag's protocol identifier to the next, and every one of those
/// bytes comes off the wire. Walking until something is not a tag lets a frame
/// made of nothing but tags decide how long this loop runs, which is a stranger
/// setting a bound in this process. A frame with more tags than this is read as
/// carrying an unrecognised EtherType, and declined the same way any other
/// unreadable frame is.
pub const MAX_VLAN_TAGS: usize = 2;

/// The largest payload an 802.3 frame may claim, and so the boundary that tells
/// a length field from an EtherType.
///
/// EtherType values start at 1536, deliberately above this, so that one field
/// can carry either and a reader can tell which. See
/// [`Frame::payload_length`].
const MAX_PAYLOAD_LEN: u16 = 1500;

/// Tag protocol identifiers that introduce a VLAN tag.
///
/// `0x8100` is the 802.1Q customer tag. `0x88A8` is the 802.1ad service tag a
/// provider adds outside it, and `0x9100` is the pre-standard spelling of the
/// same idea, still emitted by older equipment.
const VLAN_TPIDS: [u16; 3] = [0x8100, 0x88A8, 0x9100];

/// One 802.1Q tag, as it appeared on the wire.
///
/// A finding rather than framing overhead. Which VLANs a link carries is
/// something no probe can ask for, and on a trunk port it is most of what there
/// is to learn about the shape of the network on the other side of the switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct VlanTag {
    /// The tag protocol identifier this tag was introduced by, which says
    /// whether it is a customer tag or a provider's. Kept because a stack of two
    /// means something different from two of the same kind.
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
/// The type every reader of a captured frame takes. It borrows the bytes and
/// holds an offset, so [`payload`](Self::payload) hands back a slice borrowed
/// from the frame itself rather than from the view — which is the difference
/// that lets a parsed header outlive the walk that found it, and the reason
/// readers here no longer have to take a `&'a EthernetPacket<'a>` to work around
/// `pnet` lending from `&self`.
#[derive(Debug, Clone, Copy)]
pub struct Frame<'a> {
    bytes: &'a [u8],
    /// Everything past the header and any tags.
    ///
    /// The slice rather than the offset it was cut at, so that reading a
    /// payload cannot be out of bounds: a `Frame` can only be built from a
    /// buffer that had one, and there is no arithmetic left to get wrong.
    payload: &'a [u8],
    /// What the frame carries, read from behind the tags.
    ethertype: EtherType,
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
    /// On an on-link segment this is the one field that can say whether a frame
    /// came from the host it claims to: anything answering in another host's
    /// place uses that host's IP address, and cannot use its hardware address.
    pub fn source(&self) -> MacAddr {
        Self::mac_at(self.bytes, 6)
    }

    /// What the frame carries, read from behind any VLAN tags.
    ///
    /// Never a tag protocol identifier for a frame this parsed successfully,
    /// which is the whole of what this view is for.
    pub fn ethertype(&self) -> EtherType {
        self.ethertype
    }

    /// The VLAN tags this frame arrived under, outermost first. Empty for the
    /// ordinary untagged case.
    pub fn vlans(&self) -> &[VlanTag] {
        &self.tags[..self.depth]
    }

    /// Everything after the header and the tags.
    ///
    /// Borrowed from the frame rather than from this view, so a header parsed
    /// out of it may outlive the [`Frame`] that located it.
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
    /// Two framings share one field. Ethernet II puts an EtherType there and
    /// 802.3 puts a length, and they are told apart by magnitude alone: the
    /// largest legal payload is 1500 and the smallest assigned EtherType is
    /// 1536, so a value at or below 1500 is a length. That is the whole of the
    /// convention, and it is why [`ethertype`](Self::ethertype) can be a number
    /// that names no protocol.
    ///
    /// Worth reading because 802.3 framing is not a historical curiosity here:
    /// it is what carries the LLC/SNAP protocols a switch announces itself
    /// over, and a frame using it is padded to the minimum frame size, so the
    /// payload has to be cut to this length rather than read to the end.
    ///
    /// `None` for an Ethernet II frame, where the field names a protocol and
    /// says nothing about length.
    pub fn payload_length(&self) -> Option<usize> {
        (self.ethertype.0 <= MAX_PAYLOAD_LEN).then_some(usize::from(self.ethertype.0))
    }

    /// The payload, cut to the length an 802.3 header claimed.
    ///
    /// The same as [`payload`](Self::payload) for an Ethernet II frame, whose
    /// header claims no length. `None` when the header claims more than arrived,
    /// which is a truncated capture or a malformed frame and either way not
    /// something to read past the end of.
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

/// Builds the Ethernet header carrying `et` from `src_mac` to `dst_mac`.
pub fn create_header(src_mac: MacAddr, dst_mac: MacAddr, et: EtherType) -> Vec<u8> {
    craft::Ethernet::new(src_mac, dst_mac)
        .with_ethertype(et)
        .header_bytes()
}

/// Reads `frame_bytes` as an Ethernet frame, walking past any VLAN tags.
///
/// # Errors
///
/// [`PacketError::Truncated`] when there are too few bytes for a header, or for
/// the tags the header claims — which is what a cut-short capture looks like
/// from here, and also what a frame ending mid-tag looks like.
pub fn parse(frame_bytes: &'_ [u8]) -> Result<Frame<'_>> {
    let truncated = || PacketError::truncated("an Ethernet frame", ETH_HDR_LEN, frame_bytes.len());

    let mut ethertype = u16::from_be_bytes([
        *frame_bytes.get(12).ok_or_else(truncated)?,
        *frame_bytes.get(13).ok_or_else(truncated)?,
    ]);

    let mut payload_offset = ETH_HDR_LEN;
    let mut tags = [VlanTag {
        protocol: 0,
        id: 0,
        priority: 0,
        drop_eligible: false,
    }; MAX_VLAN_TAGS];
    let mut depth = 0;

    // Bounded rather than "until it is not a tag": see `MAX_VLAN_TAGS`.
    while depth < MAX_VLAN_TAGS && VLAN_TPIDS.contains(&ethertype) {
        let tci = [
            *frame_bytes.get(payload_offset).ok_or_else(truncated)?,
            *frame_bytes.get(payload_offset + 1).ok_or_else(truncated)?,
        ];
        let inner = u16::from_be_bytes([
            *frame_bytes.get(payload_offset + 2).ok_or_else(truncated)?,
            *frame_bytes.get(payload_offset + 3).ok_or_else(truncated)?,
        ]);

        tags[depth] = VlanTag::read(ethertype, tci);
        depth += 1;
        payload_offset += VLAN_TAG_LEN;
        ethertype = inner;
    }

    Ok(Frame {
        bytes: frame_bytes,
        payload: frame_bytes.get(payload_offset..).ok_or_else(truncated)?,
        ethertype: EtherType(ethertype),
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
    use pnet::packet::ethernet::EtherTypes;

    const DST: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 1);
    const SRC: MacAddr = MacAddr(0x02, 0, 0, 0, 0, 2);

    /// A frame carrying `ethertype`, wrapped in `tags` from the outside in.
    ///
    /// Each entry is `(tag protocol, tag control information)`, so a test can
    /// build a customer tag inside a provider tag and say which is which.
    fn frame_with(tags: &[(u16, u16)], ethertype: u16, payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[DST.0, DST.1, DST.2, DST.3, DST.4, DST.5]);
        bytes.extend_from_slice(&[SRC.0, SRC.1, SRC.2, SRC.3, SRC.4, SRC.5]);

        // Each tag is its protocol identifier followed by two bytes of tag
        // control information. The thing that says what comes *next* is the
        // following tag's protocol, or the real ethertype after the last one —
        // which is exactly the walk `parse` has to perform.
        for (protocol, tci) in tags {
            bytes.extend_from_slice(&protocol.to_be_bytes());
            bytes.extend_from_slice(&tci.to_be_bytes());
        }

        bytes.extend_from_slice(&ethertype.to_be_bytes());
        bytes.extend_from_slice(payload);
        bytes
    }

    /// The defect this whole view exists for.
    ///
    /// A reader taking the ethertype from its usual offset sees `0x8100` on a
    /// tagged frame and declines it — so on a trunk port every host is invisible
    /// and the scan reports an empty segment. It has to report what is *behind*
    /// the tag.
    #[test]
    fn a_tagged_frame_reports_what_is_behind_the_tag() {
        let bytes = frame_with(&[(0x8100, 0x0064)], EtherTypes::Ipv4.0, &[0xAB; 20]);
        let frame = parse(&bytes).expect("a tagged frame parses");

        assert_eq!(frame.ethertype(), EtherTypes::Ipv4);
        assert_eq!(frame.payload(), &[0xAB; 20]);
        assert_eq!(frame.source(), SRC, "a tag does not move the addresses");
        assert_eq!(frame.destination(), DST);
    }

    /// The tag is a finding, not framing overhead to step over. Which VLANs a
    /// link carries is something no probe can ask for, and the previous reader
    /// walked past it and threw it away.
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

    /// A provider tag outside a customer tag, which is what a carrier hands off.
    /// Read through only the outer one, the frame reads as carrying `0x8100`.
    #[test]
    fn a_stacked_tag_is_walked_to_the_protocol_behind_both() {
        let bytes = frame_with(
            &[(0x88A8, 0x0FA0), (0x8100, 0x0064)],
            EtherTypes::Arp.0,
            &[0xCD; 28],
        );
        let frame = parse(&bytes).expect("a QinQ frame parses");

        assert_eq!(frame.ethertype(), EtherTypes::Arp);
        assert_eq!(frame.payload(), &[0xCD; 28]);
        assert_eq!(
            frame.vlans().iter().map(|tag| tag.id).collect::<Vec<_>>(),
            vec![4000, 100],
            "outermost first"
        );
    }

    /// The walk follows bytes a stranger wrote, so it has to be the one deciding
    /// when to stop. A frame of nothing but tags must terminate and be declined,
    /// not set the length of a loop in this process.
    #[test]
    fn a_frame_of_nothing_but_tags_terminates_and_is_declined() {
        let tags: Vec<(u16, u16)> = std::iter::repeat_n((0x8100, 1), 40).collect();
        let bytes = frame_with(&tags, 0x8100, &[0u8; 8]);

        let frame = parse(&bytes).expect("it parses rather than hanging");

        assert_eq!(frame.vlans().len(), MAX_VLAN_TAGS, "the walk stopped");
        assert_eq!(
            frame.ethertype(),
            EtherType(0x8100),
            "and reports a tag protocol as the ethertype, which every reader declines"
        );
    }

    /// A capture truncated to its snapshot length can end anywhere, including
    /// inside a tag. Reading the ethertype from past the end would invent one;
    /// the payload offset would then point past the buffer.
    #[test]
    fn a_frame_ending_inside_a_tag_is_refused_rather_than_read_past() {
        let bytes = frame_with(&[(0x8100, 0x0064)], EtherTypes::Ipv4.0, &[]);

        for cut in ETH_HDR_LEN..bytes.len() {
            assert!(
                parse(&bytes[..cut]).is_err(),
                "a frame cut to {cut} bytes claims a tag it does not carry"
            );
        }

        assert!(parse(&bytes).is_ok(), "the whole frame still parses");
    }

    /// The ordinary untagged case, which every other reader in the crate depends
    /// on continuing to work exactly as it did.
    #[test]
    fn an_untagged_frame_reads_as_it_always_did() {
        let bytes = frame_with(&[], EtherTypes::Ipv4.0, &[0x11; 20]);
        let frame = parse(&bytes).expect("an untagged frame parses");

        assert_eq!(frame.ethertype(), EtherTypes::Ipv4);
        assert_eq!(frame.payload(), &[0x11; 20]);
        assert!(frame.vlans().is_empty());
    }
}
