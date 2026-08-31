// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Link Layer Discovery Protocol (IEEE 802.1AB)
//!
//! What the equipment on a link says about itself, unprompted.
//!
//! A managed switch emits one of these to each of its ports every thirty seconds
//! or so, naming itself, naming the port you are plugged into, and listing what
//! it is capable of. There is no request. Nothing here builds a frame, because
//! there is no question to ask: the answer arrives on its own or not at all.
//!
//! That makes it unlike everything else this module reads. A port scan learns
//! what a host will admit to; this learns what the *network* says, from the one
//! device in a position to know — and it is the only source in this crate for
//! two facts no probe can obtain: **which switch this machine is attached to,
//! and on which port.**
//!
//! ## What it is worth trusting about
//!
//! An advertisement is unauthenticated and arrives from whoever cared to send
//! one. Anything on the link can claim to be a switch. What makes the ordinary
//! case believable is not the protocol but the position: the frames are sent to
//! a group address (`01:80:C2:00:00:0E`) that conforming bridges do **not**
//! forward, so one that arrives came from something on this segment. That is a
//! statement about where the sender is, never about whether it told the truth.
//!
//! The one distinction this module insists on is [`Capabilities`]: a device
//! reports what it *supports* and, separately, what it has *enabled*. Only the
//! second says anything about what the box is doing, and conflating them would
//! call every switch with a routing licence a router.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pnet_base::MacAddr;
use pnet_packet::ethernet::EtherType;

use crate::protocols::ethernet::Frame;
use crate::protocols::text::field as text;

/// The EtherType carrying an LLDP data unit.
pub const ETHERTYPE: EtherType = EtherType(0x88CC);

/// The group addresses LLDP is sent to, all three of which conforming bridges
/// constrain rather than forward.
///
/// `...:0E` is the nearest-bridge address and by far the usual one. The other
/// two exist so an advertisement can be constrained to a different scope, and
/// are read the same way because what they change is how far the frame
/// travels — not what it says.
const GROUP_ADDRESSES: [MacAddr; 3] = [
    MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E),
    MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x03),
    MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x00),
];

/// How many type-length-value records are read out of one data unit.
///
/// The walk is driven by lengths the sender chose, so the sender decides how
/// many times this loop runs unless something else does. A real advertisement
/// carries somewhere between four and twenty; this is far above anything
/// legitimate and still a bound.
const MAX_TLVS: usize = 128;

/// The 802.1 organizationally-unique identifier, under which the VLAN a port is
/// untagged into is advertised.
const OUI_802_1: [u8; 3] = [0x00, 0x80, 0xC2];

/// The 802.1 subtype carrying the port's own VLAN identifier.
const SUBTYPE_PORT_VLAN: u8 = 1;

// TLV type numbers, from IEEE 802.1AB-2016 Table 8-1.
const TLV_END: u8 = 0;
const TLV_CHASSIS_ID: u8 = 1;
const TLV_PORT_ID: u8 = 2;
const TLV_TTL: u8 = 3;
const TLV_PORT_DESCRIPTION: u8 = 4;
const TLV_SYSTEM_NAME: u8 = 5;
const TLV_SYSTEM_DESCRIPTION: u8 = 6;
const TLV_CAPABILITIES: u8 = 7;
const TLV_MANAGEMENT_ADDRESS: u8 = 8;
const TLV_ORGANIZATIONALLY_SPECIFIC: u8 = 127;

// Identifier subtypes that say how to read the bytes after them.
//
// **The two tables do not agree, and that is the trap.** IEEE 802.1AB-2016
// numbers chassis subtypes in Table 8-2 and port subtypes in Table 8-3, and the
// same meaning sits at a different number in each: a MAC address is 4 for a
// chassis and 3 for a port, a network address 5 and 4. Read with one table, a
// port named `GigabitEthernet1/0/14` is decoded as a network address — which
// fails quietly, because subtype 5 means *interface name* for a port and the
// bytes parse as neither.
const CHASSIS_SUBTYPE_MAC: u8 = 4;
const CHASSIS_SUBTYPE_NETWORK: u8 = 5;
const PORT_SUBTYPE_MAC: u8 = 3;
const PORT_SUBTYPE_NETWORK: u8 = 4;

/// Address family numbers as IANA assigns them, used by the management-address
/// TLV to say which kind of address follows.
const AFN_IPV4: u8 = 1;
const AFN_IPV6: u8 = 2;

/// How a device or a port names itself.
///
/// The value's meaning is decided by a subtype byte in front of it, so this is
/// an enum rather than a string: a chassis identified by its MAC address and one
/// identified by a name a technician typed are not the same kind of claim, and
/// rendering both as text would lose which of the two is a stable identity.
///
/// `#[non_exhaustive]`: the two subtype tables between them number nine kinds of
/// identifier and this reads three, folding the rest into
/// [`Other`](Self::Other). A subtype that turns out to be worth its own shape
/// becomes a variant, and that must not be a breaking change.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identifier<'a> {
    /// A hardware address. The most useful chassis identifier there is: it can
    /// be matched against a MAC seen anywhere else on the segment.
    Mac(MacAddr),
    /// A network address the sender is reachable at.
    Network(IpAddr),
    /// An interface name, an alias, or a locally-assigned string — whichever of
    /// those the subtype named. All are text a person configured.
    Text(&'a str),
    /// A subtype this module does not interpret, kept as it arrived.
    ///
    /// Preserved rather than dropped because an identifier nobody can read is
    /// still an identifier that can be compared with the next one from the same
    /// device.
    Other {
        /// The subtype byte, as sent.
        subtype: u8,
        /// Everything after it.
        bytes: &'a [u8],
    },
}

/// What a device says it can do, and what it says it is doing.
///
/// **The two are not the same claim and this type will not let them be
/// confused.** A switch with a routing licence it has never been given an
/// interface for reports routing as supported and not enabled; reading the first
/// as behaviour would put a router on every access switch in the building.
/// Every predicate here reads *enabled*.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capabilities {
    supported: u16,
    enabled: u16,
}

impl Capabilities {
    // Bit positions from IEEE 802.1AB-2016 Table 8-4.
    const REPEATER: u16 = 1 << 1;
    const BRIDGE: u16 = 1 << 2;
    const WLAN_ACCESS_POINT: u16 = 1 << 3;
    const ROUTER: u16 = 1 << 4;
    const TELEPHONE: u16 = 1 << 5;
    const STATION_ONLY: u16 = 1 << 7;

    /// Whether the device is switching frames.
    pub fn is_bridge(self) -> bool {
        self.enabled & Self::BRIDGE != 0
    }

    /// Whether the device is routing.
    pub fn is_router(self) -> bool {
        self.enabled & Self::ROUTER != 0
    }

    /// Whether the device is serving a wireless network.
    pub fn is_wlan_access_point(self) -> bool {
        self.enabled & Self::WLAN_ACCESS_POINT != 0
    }

    /// Whether the device is a telephone, which is what an IP handset announces
    /// itself as.
    pub fn is_telephone(self) -> bool {
        self.enabled & Self::TELEPHONE != 0
    }

    /// Whether the device forwards at the physical layer without reading frames.
    pub fn is_repeater(self) -> bool {
        self.enabled & Self::REPEATER != 0
    }

    /// Whether the device says it is an endpoint and nothing else — it does not
    /// forward for anybody.
    ///
    /// A positive claim rather than the absence of the others, which is why it
    /// is worth reading: a workstation that says this has told you it is not
    /// part of the infrastructure.
    pub fn is_station_only(self) -> bool {
        self.enabled & Self::STATION_ONLY != 0
    }

    /// The raw capability bits, as supported and as enabled in that order.
    ///
    /// For a caller that wants a bit this type has no predicate for. Reading the
    /// first of the two as a statement about behaviour is the mistake this type
    /// exists to prevent, so it is handed over only alongside the second.
    pub fn bits(self) -> (u16, u16) {
        (self.supported, self.enabled)
    }
}

/// One device's advertisement of itself.
///
/// Every field is optional because every field can be absent: the standard
/// requires only the chassis identifier, the port identifier and the time to
/// live, and plenty of equipment sends little more. A field that is `None` was
/// not sent, and never means the device denied it.
///
/// `#[non_exhaustive]`: these are eight of the TLVs IEEE 802.1AB defines and the
/// standard keeps adding more, so a field arriving here is a matter of time. A
/// caller reads this and never builds one; [`Default`] is what to start from if
/// one is needed for a test.
#[non_exhaustive]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Advertisement<'a> {
    /// How the device names itself. Required by the standard.
    pub chassis_id: Option<Identifier<'a>>,

    /// How the device names the port this frame left by — which is the port
    /// this machine is plugged into.
    ///
    /// The single most useful thing here, and the one no probe can obtain: it
    /// locates this machine in somebody's wiring.
    pub port_id: Option<Identifier<'a>>,

    /// How many seconds this advertisement stays valid. Zero is how a device
    /// withdraws one as it shuts the port down.
    pub ttl: Option<u16>,

    /// The device's administratively assigned name, which on a managed network
    /// is its hostname.
    pub system_name: Option<&'a str>,

    /// What the device says it is: usually a model and firmware version, in a
    /// format nobody has ever standardised.
    pub system_description: Option<&'a str>,

    /// What the device calls this port in its own configuration.
    pub port_description: Option<&'a str>,

    /// What the device can do, and what it is doing. See [`Capabilities`].
    pub capabilities: Option<Capabilities>,

    /// An address the device is managed at, where it advertised one.
    ///
    /// The first, where several were sent. A device may advertise one per
    /// address family and per management interface, and any of them answers the
    /// question this is read for — how to reach the box — so the alternatives
    /// are not carried. A caller needing all of them wants the TLVs.
    pub management_address: Option<IpAddr>,

    /// The VLAN this port places untagged traffic in, where the device
    /// advertised one.
    ///
    /// From the 802.1 organizationally-specific TLV rather than the base
    /// standard, so a device may speak LLDP fluently and never send it.
    pub port_vlan: Option<u16>,
}

/// Reads `frame` as an LLDP advertisement, or `None` if it is not one.
///
/// Declines rather than guesses at every step, which for this protocol means a
/// device that sent one field badly still contributes the rest: a TLV whose
/// value cannot be read is skipped, one whose length runs past the frame ends
/// the walk, and either way what was already read is kept. Refusing the whole
/// advertisement would let one vendor's malformed description cost the switch
/// name and the port beside it, and a capture cut at its snapshot length cost
/// them for no reason at all.
///
/// The end-of-unit record is optional in IEEE 802.1AB-2016, so a unit that
/// simply stops is an ordinary one rather than a truncated one, and reads the
/// same way.
///
/// # What is checked before anything is read
///
/// The EtherType, and nothing else. The destination is deliberately *not*
/// required to be one of the group addresses: a frame that reached this capture
/// with LLDP's EtherType is an advertisement whoever it was addressed to, and on
/// a mirrored port the destination is somebody else's. Where the distinction
/// matters — whether the sender is on *this* segment — the caller has the
/// destination and [`addressed_to_a_bridge_group`] to ask with.
pub fn parse<'a>(frame: &Frame<'a>) -> Option<Advertisement<'a>> {
    if frame.ethertype() != ETHERTYPE {
        return None;
    }

    let mut advertisement = Advertisement::default();
    let mut rest = frame.payload();
    let mut seen = 0usize;

    while seen < MAX_TLVS {
        // A short tail ends the walk and keeps what is in front of it, which is
        // what a capture cut at its snapshot length looks like from here, and
        // what a unit that omits the optional end record looks like too. See the
        // policy in the [module documentation](crate::protocols).
        let Some((kind, value, remainder)) = next_tlv(rest) else {
            break;
        };
        if kind == TLV_END {
            break;
        }
        rest = remainder;
        seen += 1;

        // Every field takes the first readable value and keeps it. A unit is
        // meant to carry each of these once, so a second is malformed, and the
        // reading that costs least is to believe what already parsed. Assigning
        // unconditionally let a second unreadable record erase a good value: a
        // frame naming the switch and then repeating the chassis TLV badly
        // reported no switch at all.
        match kind {
            TLV_CHASSIS_ID => keep_first(
                &mut advertisement.chassis_id,
                identifier(value, CHASSIS_SUBTYPE_MAC, CHASSIS_SUBTYPE_NETWORK),
            ),
            TLV_PORT_ID => keep_first(
                &mut advertisement.port_id,
                identifier(value, PORT_SUBTYPE_MAC, PORT_SUBTYPE_NETWORK),
            ),
            TLV_TTL => keep_first(
                &mut advertisement.ttl,
                value
                    .first_chunk::<2>()
                    .map(|bytes| u16::from_be_bytes(*bytes)),
            ),
            TLV_PORT_DESCRIPTION => keep_first(&mut advertisement.port_description, text(value)),
            TLV_SYSTEM_NAME => keep_first(&mut advertisement.system_name, text(value)),
            TLV_SYSTEM_DESCRIPTION => {
                keep_first(&mut advertisement.system_description, text(value));
            }
            TLV_CAPABILITIES => keep_first(&mut advertisement.capabilities, capabilities(value)),
            TLV_MANAGEMENT_ADDRESS => {
                // A device may send one per family and per interface, and the
                // question this answers is "how do I reach it", which the first
                // already settles.
                keep_first(&mut advertisement.management_address, management(value));
            }
            TLV_ORGANIZATIONALLY_SPECIFIC => {
                keep_first(&mut advertisement.port_vlan, port_vlan(value));
            }
            _ => {}
        }
    }

    // A data unit carrying none of the three mandatory fields is not one this
    // has read successfully — it is bytes that happened to arrive under LLDP's
    // EtherType, and crediting a device with an empty advertisement would put a
    // finding on the record that nothing said.
    let read_something = advertisement.chassis_id.is_some()
        || advertisement.port_id.is_some()
        || advertisement.ttl.is_some();

    read_something.then_some(advertisement)
}

/// Records `value` in `field` if the field is still empty and the value is
/// readable.
///
/// What makes reading monotone: a longer prefix of a unit reports everything a
/// shorter one did, so a record arriving later can add a field and never take
/// one away. The fuzz target holds exactly that.
fn keep_first<T>(field: &mut Option<T>, value: Option<T>) {
    if field.is_none() {
        *field = value;
    }
}

/// Whether `destination` is one of the group addresses a conforming bridge
/// constrains rather than forwards.
///
/// The reason an advertisement is believable about *where* its sender is. It
/// says nothing about whether the sender told the truth, and a frame captured on
/// a mirror port may legitimately be addressed elsewhere.
pub fn addressed_to_a_bridge_group(destination: MacAddr) -> bool {
    GROUP_ADDRESSES.contains(&destination)
}

/// Splits one type-length-value record off the front of `bytes`.
///
/// Returns the type, the value, and whatever follows. `None` when there are too
/// few bytes for a header or for the length the header claims — the second being
/// the case that matters, since the length comes off the wire.
fn next_tlv(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let header = bytes.first_chunk::<2>()?;

    // Seven bits of type and nine of length, packed across the two bytes.
    let kind = header[0] >> 1;
    let length = usize::from(u16::from_be_bytes([header[0] & 1, header[1]]));

    let value = bytes.get(2..2 + length)?;
    let remainder = bytes.get(2 + length..)?;

    Some((kind, value, remainder))
}

/// Reads a chassis or port identifier: one subtype byte, then a value whose
/// shape that byte decides.
///
/// `mac` and `network` are the subtype numbers meaning those two things *in the
/// table this identifier is numbered by*, which is why they are arguments rather
/// than constants read from here. See the constants for why that matters.
fn identifier(value: &[u8], mac: u8, network: u8) -> Option<Identifier<'_>> {
    let (subtype, id) = value.split_first()?;
    if id.is_empty() {
        return None;
    }

    match *subtype {
        found if found == mac => id.first_chunk::<6>().map(|bytes| {
            Identifier::Mac(MacAddr::new(
                bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5],
            ))
        }),
        found if found == network => {
            let (family, address) = id.split_first()?;
            address_of(*family, address).map(Identifier::Network)
        }
        // Every remaining subtype is a name somebody configured: an interface
        // name, an alias, a port component, or a locally assigned string.
        other => match text(id) {
            Some(name) => Some(Identifier::Text(name)),
            None => Some(Identifier::Other {
                subtype: other,
                bytes: id,
            }),
        },
    }
}

/// Reads the capability TLV: what is supported, then what is enabled.
fn capabilities(value: &[u8]) -> Option<Capabilities> {
    let bytes = value.first_chunk::<4>()?;
    Some(Capabilities {
        supported: u16::from_be_bytes([bytes[0], bytes[1]]),
        enabled: u16::from_be_bytes([bytes[2], bytes[3]]),
    })
}

/// Reads the address out of a management-address TLV.
///
/// The TLV's shape is a length byte covering the family and the address
/// together, then the family, then the address — followed by interface
/// numbering and an object identifier this does not read, since neither says
/// how to reach the device.
fn management(value: &[u8]) -> Option<IpAddr> {
    let (length, rest) = value.split_first()?;

    // The length counts the family byte as well as the address, so a length of
    // one describes an address of nothing.
    let length = usize::from(*length);
    let string = rest.get(..length)?;
    let (family, address) = string.split_first()?;

    address_of(*family, address)
}

/// Reads the VLAN identifier out of an organizationally-specific TLV, if that is
/// what this one carries.
fn port_vlan(value: &[u8]) -> Option<u16> {
    let (oui, rest) = value.split_at_checked(OUI_802_1.len())?;
    if oui != OUI_802_1 {
        return None;
    }

    let (subtype, vlan) = rest.split_first()?;
    if *subtype != SUBTYPE_PORT_VLAN {
        return None;
    }

    vlan.first_chunk::<2>()
        .map(|bytes| u16::from_be_bytes(*bytes))
}

/// An address of the family IANA numbers as `family`, or `None` for a family
/// this does not read or too few bytes to hold one.
///
/// Takes the address's own width from the front and ignores anything past it,
/// rather than requiring the record to be exactly that long. A device that pads
/// the field still names an address, and this reads the bytes the family says
/// are the address.
fn address_of(family: u8, address: &[u8]) -> Option<IpAddr> {
    match family {
        AFN_IPV4 => address
            .first_chunk::<4>()
            .map(|bytes| IpAddr::V4(Ipv4Addr::from(*bytes))),
        AFN_IPV6 => address
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
    use crate::protocols::sizes::ETH_HDR_LEN;

    pub(crate) const SWITCH_MAC: MacAddr = MacAddr(0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x5F);
    const NEAREST_BRIDGE: MacAddr = MacAddr(0x01, 0x80, 0xC2, 0x00, 0x00, 0x0E);

    /// One TLV: seven bits of type and nine of length, packed across two bytes.
    ///
    /// Written out here rather than reusing the parser's own arithmetic, so that
    /// a mistake in the packing cannot cancel out against the same mistake in
    /// the reading.
    fn tlv(kind: u8, value: &[u8]) -> Vec<u8> {
        let length = value.len();
        assert!(length < 512, "a TLV value is nine bits of length");

        let mut bytes = vec![
            (kind << 1) | u8::try_from(length >> 8).expect("one bit"),
            u8::try_from(length & 0xFF).expect("eight bits"),
        ];
        bytes.extend_from_slice(value);
        bytes
    }

    /// An LLDP frame carrying `tlvs`, closed with the end-of-unit record most
    /// equipment sends.
    fn frame_of(tlvs: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = unterminated_frame_of(tlvs);
        bytes.extend_from_slice(&tlv(TLV_END, &[]));
        bytes
    }

    /// The same, stopping at the last record.
    ///
    /// IEEE 802.1AB-2016 makes the end-of-unit record optional, so this is a
    /// well-formed unit rather than a broken one, and it is also what every
    /// truncated capture looks like.
    fn unterminated_frame_of(tlvs: &[Vec<u8>]) -> Vec<u8> {
        let mut bytes = ethernet::build_header(SWITCH_MAC, NEAREST_BRIDGE, ETHERTYPE);
        for tlv in tlvs {
            bytes.extend_from_slice(tlv);
        }
        bytes
    }

    fn chassis_mac(mac: MacAddr) -> Vec<u8> {
        tlv(
            TLV_CHASSIS_ID,
            &[
                CHASSIS_SUBTYPE_MAC,
                mac.0,
                mac.1,
                mac.2,
                mac.3,
                mac.4,
                mac.5,
            ],
        )
    }

    /// A port identified by name: subtype 5 in the *port* table, which is
    /// subtype 5 in the chassis table too — but means a network address there.
    fn port_named(name: &str) -> Vec<u8> {
        let mut value = vec![5u8];
        value.extend_from_slice(name.as_bytes());
        tlv(TLV_PORT_ID, &value)
    }

    /// A port identified by its own hardware address, which is subtype 3 for a
    /// port and 4 for a chassis.
    fn port_mac(mac: MacAddr) -> Vec<u8> {
        tlv(
            TLV_PORT_ID,
            &[PORT_SUBTYPE_MAC, mac.0, mac.1, mac.2, mac.3, mac.4, mac.5],
        )
    }

    fn capability_tlv(supported: u16, enabled: u16) -> Vec<u8> {
        let mut value = supported.to_be_bytes().to_vec();
        value.extend_from_slice(&enabled.to_be_bytes());
        tlv(TLV_CAPABILITIES, &value)
    }

    /// A complete advertisement from a managed switch that is also routing:
    /// named `core-sw-02`, on port `GigabitEthernet1/0/14`, untagged traffic in
    /// VLAN 40, managed at `10.0.0.2`.
    ///
    /// Shared with the listener's tests, which read this protocol and CDP
    /// through one normalising step and need a frame of each carrying the same
    /// four facts. Deliberately the same four values as
    /// [`cdp::tests::switch_announcement`](crate::protocols::cdp::tests::switch_announcement),
    /// so a test can assert the two arrive identically rather than assert twice.
    pub(crate) fn switch_announcement() -> Vec<u8> {
        frame_of(&[
            chassis_mac(SWITCH_MAC),
            port_named("GigabitEthernet1/0/14"),
            tlv(TLV_TTL, &120u16.to_be_bytes()),
            tlv(TLV_SYSTEM_NAME, b"core-sw-02"),
            capability_tlv(
                Capabilities::BRIDGE | Capabilities::ROUTER,
                Capabilities::BRIDGE | Capabilities::ROUTER,
            ),
            tlv(
                TLV_ORGANIZATIONALLY_SPECIFIC,
                &[0x00, 0x80, 0xC2, SUBTYPE_PORT_VLAN, 0x00, 0x28],
            ),
            tlv(
                TLV_MANAGEMENT_ADDRESS,
                &[5, AFN_IPV4, 10, 0, 0, 2, 0x03, 0, 0, 0, 1, 0],
            ),
        ])
    }

    /// The whole walk, over the advertisement a managed switch actually sends.
    ///
    /// One test rather than one per field, because the fields are read by one
    /// loop: what can break is the offset arithmetic that steps between them,
    /// and that breaks for all of them at once or none.
    #[test]
    fn a_switch_advertisement_is_read_field_by_field() {
        let bytes = frame_of(&[
            chassis_mac(SWITCH_MAC),
            port_named("GigabitEthernet1/0/14"),
            tlv(TLV_TTL, &120u16.to_be_bytes()),
            tlv(TLV_SYSTEM_NAME, b"core-sw-02"),
            tlv(TLV_SYSTEM_DESCRIPTION, b"Cisco IOS Software, C2960X"),
            tlv(TLV_PORT_DESCRIPTION, b"uplink to rack 4"),
            capability_tlv(
                Capabilities::BRIDGE | Capabilities::ROUTER,
                Capabilities::BRIDGE,
            ),
            // 802.1 organizationally specific: the port's untagged VLAN.
            tlv(
                TLV_ORGANIZATIONALLY_SPECIFIC,
                &[0x00, 0x80, 0xC2, SUBTYPE_PORT_VLAN, 0x00, 0x28],
            ),
            // Management address: length covers the family byte and the address.
            tlv(
                TLV_MANAGEMENT_ADDRESS,
                &[5, AFN_IPV4, 10, 0, 0, 2, 0x03, 0, 0, 0, 1, 0],
            ),
        ]);

        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let advertisement = parse(&frame).expect("an LLDP advertisement");

        assert_eq!(advertisement.chassis_id, Some(Identifier::Mac(SWITCH_MAC)));
        assert_eq!(
            advertisement.port_id,
            Some(Identifier::Text("GigabitEthernet1/0/14"))
        );
        assert_eq!(advertisement.ttl, Some(120));
        assert_eq!(advertisement.system_name, Some("core-sw-02"));
        assert_eq!(
            advertisement.system_description,
            Some("Cisco IOS Software, C2960X")
        );
        assert_eq!(advertisement.port_description, Some("uplink to rack 4"));
        assert_eq!(advertisement.port_vlan, Some(40));
        assert_eq!(
            advertisement.management_address,
            Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)))
        );
        assert!(addressed_to_a_bridge_group(frame.destination()));
    }

    /// Chassis and port identifiers are numbered by two different tables, and
    /// the same number means different things in each.
    ///
    /// This was wrong when it was first written: one table was used for both, so
    /// a port named `GigabitEthernet1/0/14` — subtype 5, an interface name —
    /// was read against the chassis table, where 5 is a network address. It
    /// produced no error and no value, which is how a reader loses the single
    /// most useful field in the protocol without anybody noticing.
    #[test]
    fn a_subtype_is_read_against_the_table_its_identifier_is_numbered_by() {
        let bytes = frame_of(&[chassis_mac(SWITCH_MAC), port_named("Gi1/0/14")]);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let advertisement = parse(&frame).expect("an advertisement");

        assert_eq!(
            advertisement.chassis_id,
            Some(Identifier::Mac(SWITCH_MAC)),
            "chassis subtype 4 is a hardware address"
        );
        assert_eq!(
            advertisement.port_id,
            Some(Identifier::Text("Gi1/0/14")),
            "port subtype 5 is an interface name, not the network address it is \
             for a chassis"
        );

        // And the other direction: a port's hardware address is subtype 3.
        let port_mac_address = MacAddr(0x00, 0x1B, 0x2C, 0x3D, 0x4E, 0x60);
        let bytes = frame_of(&[chassis_mac(SWITCH_MAC), port_mac(port_mac_address)]);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        assert_eq!(
            parse(&frame).expect("an advertisement").port_id,
            Some(Identifier::Mac(port_mac_address)),
            "port subtype 3 is a hardware address, where 3 is a port component \
             for a chassis"
        );
    }

    /// The distinction [`Capabilities`] exists for.
    ///
    /// A switch licensed to route but not routing advertises the bit as
    /// supported and not as enabled. Read from the wrong half of the TLV, every
    /// such switch becomes a router — and on a campus network that is most of
    /// them.
    #[test]
    fn a_capability_that_is_supported_but_not_enabled_is_not_a_claim() {
        let bytes = frame_of(&[
            chassis_mac(SWITCH_MAC),
            capability_tlv(
                Capabilities::BRIDGE | Capabilities::ROUTER | Capabilities::WLAN_ACCESS_POINT,
                Capabilities::BRIDGE,
            ),
        ]);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let capabilities = parse(&frame)
            .expect("an advertisement")
            .capabilities
            .expect("capabilities");

        assert!(capabilities.is_bridge(), "it said it is bridging");
        assert!(
            !capabilities.is_router(),
            "it said it could route, which is not the same as doing it"
        );
        assert!(!capabilities.is_wlan_access_point());
    }

    /// The type and length share a byte: seven bits of type, then the top bit of
    /// a nine-bit length. A reader that takes the length from the second byte
    /// alone truncates every value longer than 255 — and a system description is
    /// routinely longer than that.
    #[test]
    fn a_value_longer_than_a_byte_can_count_is_read_whole() {
        let long = "x".repeat(400);
        let bytes = frame_of(&[
            chassis_mac(SWITCH_MAC),
            tlv(TLV_SYSTEM_DESCRIPTION, long.as_bytes()),
            tlv(TLV_SYSTEM_NAME, b"after-the-long-one"),
        ]);

        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");
        let advertisement = parse(&frame).expect("an LLDP advertisement");

        assert_eq!(advertisement.system_description, Some(long.as_str()));
        assert_eq!(
            advertisement.system_name,
            Some("after-the-long-one"),
            "and the walk resumed at the right place afterwards"
        );
    }

    /// The lengths driving the walk are the sender's. One claiming more bytes
    /// than arrived must stop the walk, not read whatever follows the buffer.
    #[test]
    fn a_length_running_past_the_frame_is_refused() {
        let mut bytes = frame_of(&[chassis_mac(SWITCH_MAC)]);
        // A TLV claiming 500 bytes of system name, with none behind it.
        bytes.extend_from_slice(&[(TLV_SYSTEM_NAME << 1) | 1, 0xF4]);

        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        // The end-of-unit TLV sits before the malformed one, so the walk stops
        // cleanly and keeps what it had already read.
        let advertisement = parse(&frame).expect("what was read before the end");
        assert_eq!(advertisement.chassis_id, Some(Identifier::Mac(SWITCH_MAC)));
        assert_eq!(advertisement.system_name, None);
    }

    /// A truncated capture ends mid-TLV, and what was read before the cut is
    /// kept rather than thrown away with it.
    ///
    /// **This test used to pass without running.** Its only assertion sat inside
    /// `if let Some(advertisement) = parse(&frame)`, and `parse` returned `None`
    /// for every cut it generated, so the block never executed and the test
    /// passed for a parser that declined unconditionally. Which is very nearly
    /// what the parser did: `next_tlv(rest)?` discarded the whole advertisement
    /// on a short tail, including the chassis and port identifiers the doc
    /// promises to keep. The floor below is what stops that recurring, because
    /// a version that declines cannot reach it.
    #[test]
    fn a_truncated_advertisement_keeps_the_fields_that_arrived_whole() {
        let bytes = unterminated_frame_of(&[
            chassis_mac(SWITCH_MAC),
            port_named("Gi1/0/14"),
            tlv(TLV_TTL, &120u16.to_be_bytes()),
            tlv(
                TLV_SYSTEM_DESCRIPTION,
                b"a description long enough to cut inside",
            ),
        ]);

        // Where the chassis and port identifiers both end: 14 bytes of Ethernet
        // header, then each TLV's two header bytes and its value.
        let chassis = chassis_mac(SWITCH_MAC).len();
        let port = port_named("Gi1/0/14").len();
        let both_read = ETH_HDR_LEN + chassis + port;

        let mut kept = 0usize;
        for cut in both_read..bytes.len() {
            let frame = ethernet::parse(&bytes[..cut]).expect("a frame");
            let Some(advertisement) = parse(&frame) else {
                panic!("a frame cut to {cut} bytes lost an advertisement it had already read");
            };

            assert_eq!(
                advertisement.chassis_id,
                Some(Identifier::Mac(SWITCH_MAC)),
                "the chassis identifier was read whole and then discarded, at {cut} bytes"
            );
            assert_eq!(
                advertisement.port_id,
                Some(Identifier::Text("Gi1/0/14")),
                "the port identifier was read whole and then discarded, at {cut} bytes"
            );
            assert!(
                advertisement.ttl.is_none() || cut >= both_read + 4,
                "a TTL was reported from a frame cut to {cut} bytes"
            );
            kept += 1;
        }

        assert!(
            kept >= 30,
            "only {kept} truncations reached the assertions; the test is not measuring what it names"
        );
    }

    /// The end-of-unit record is optional in IEEE 802.1AB-2016, so a unit that
    /// simply stops is an ordinary one. Reading it as truncated cost the whole
    /// advertisement.
    #[test]
    fn a_unit_with_no_end_record_reads_as_one_that_has_it() {
        let tlvs = [chassis_mac(SWITCH_MAC), tlv(TLV_SYSTEM_NAME, b"core-01")];

        let without_end = unterminated_frame_of(&tlvs);
        let with_end = frame_of(&tlvs);

        fn read(bytes: &[u8]) -> Advertisement<'_> {
            let frame = ethernet::parse(bytes).expect("a frame");
            parse(&frame).expect("an advertisement")
        }

        assert_eq!(read(&without_end), read(&with_end));
        assert_eq!(read(&without_end).system_name, Some("core-01"));
    }

    /// The property the fuzz target holds, over generated units rather than one
    /// worked example: **reading further only ever adds to what was read.**
    ///
    /// Two things make it true, and it is false without either. A short tail
    /// ends the walk and keeps what is in front of it, rather than discarding
    /// the unit; and each field takes the first readable value, so a later
    /// record cannot erase one that already parsed.
    ///
    /// Written here as well as in `fuzz/fuzz_targets/wire/ethernet_frame.rs`
    /// because a property only a fuzz campaign holds is a property nobody runs.
    #[test]
    fn reading_further_never_takes_away_a_field_already_read() {
        proptest::proptest!(|(
            tlvs in proptest::collection::vec(
                (0u8..=8u8, proptest::collection::vec(proptest::prelude::any::<u8>(), 0..24)),
                1..12,
            ),
        )| {
            let bytes = unterminated_frame_of(
                &tlvs
                    .iter()
                    .map(|(kind, value)| tlv(*kind, value))
                    .collect::<Vec<_>>(),
            );
            let frame = ethernet::parse(&bytes).expect("a frame");

            if let Some(whole) = parse(&frame) {
                for cut in ETH_HDR_LEN..bytes.len() {
                    let shorter = ethernet::parse(&bytes[..cut]).expect("a frame");
                    let Some(before) = parse(&shorter) else {
                        continue;
                    };

                    // A field a shorter run reported is the field the whole run
                    // reports. One it never reached is absent, and says nothing.
                    if before.chassis_id.is_some() {
                        proptest::prop_assert_eq!(before.chassis_id, whole.chassis_id);
                    }
                    if before.port_id.is_some() {
                        proptest::prop_assert_eq!(before.port_id, whole.port_id);
                    }
                    if before.ttl.is_some() {
                        proptest::prop_assert_eq!(before.ttl, whole.ttl);
                    }
                    if before.system_name.is_some() {
                        proptest::prop_assert_eq!(before.system_name, whole.system_name);
                    }
                    if before.capabilities.is_some() {
                        proptest::prop_assert_eq!(before.capabilities, whole.capabilities);
                    }
                }
            }
        });
    }

    /// The half of that property a worked example states outright: a second
    /// record of a kind a unit carries once must not erase the first.
    ///
    /// Assigning unconditionally, a switch that named itself and then repeated
    /// the chassis TLV badly was reported as no switch at all.
    #[test]
    fn a_second_unreadable_record_does_not_erase_the_first() {
        let good = chassis_mac(SWITCH_MAC);
        // Subtype 4 says a MAC address, and four bytes are not one.
        let bad = tlv(TLV_CHASSIS_ID, &[CHASSIS_SUBTYPE_MAC, 1, 2, 3, 4]);

        let bytes = frame_of(&[good, bad, tlv(TLV_SYSTEM_NAME, b"core-01")]);
        let frame = ethernet::parse(&bytes).expect("a frame");
        let advertisement = parse(&frame).expect("an advertisement");

        assert_eq!(advertisement.chassis_id, Some(Identifier::Mac(SWITCH_MAC)));
        assert_eq!(advertisement.system_name, Some("core-01"));
    }

    /// A sender sets the length of this walk unless something else does. A unit
    /// made of nothing but TLVs must terminate.
    #[test]
    fn a_unit_of_endless_tlvs_terminates() {
        let filler: Vec<Vec<u8>> =
            std::iter::repeat_n(tlv(TLV_SYSTEM_NAME, b"a"), MAX_TLVS * 4).collect();
        let mut tlvs = vec![chassis_mac(SWITCH_MAC)];
        tlvs.extend(filler);

        let bytes = frame_of(&tlvs);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        let advertisement = parse(&frame).expect("it returns rather than hanging");
        assert_eq!(advertisement.chassis_id, Some(Identifier::Mac(SWITCH_MAC)));
    }

    /// Bytes that arrived under LLDP's EtherType and said nothing are not an
    /// advertisement. Reporting an empty one would put a device on the record
    /// that never named itself.
    #[test]
    fn a_unit_carrying_no_mandatory_field_is_not_an_advertisement() {
        let bytes = frame_of(&[tlv(TLV_PORT_DESCRIPTION, b"only a description")]);
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        assert_eq!(parse(&frame), None);
    }

    /// An ordinary frame is not an advertisement, which is the common case on
    /// any capture wide enough to see one.
    #[test]
    fn a_frame_of_another_protocol_is_declined() {
        let bytes = ethernet::build_header(
            SWITCH_MAC,
            NEAREST_BRIDGE,
            pnet_packet::ethernet::EtherTypes::Ipv4,
        );
        let frame = ethernet::parse(&bytes).expect("an Ethernet frame");

        assert_eq!(parse(&frame), None);
    }
}
