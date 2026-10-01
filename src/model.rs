// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The domain vocabulary
//!
//! The types a scan is described in: a [`Host`](host::Host), a
//! [`Port`](port::Port), the addresses to visit ([`IpSet`](ip::set::IpSet) and
//! [`TargetMap`](target::TargetMap)), the [order](order::Permutation) a plan
//! is asked in, and what the capture saw on the way
//! ([`CaptureCounts`](capture::CaptureCounts)).
//!
//! [`parse`] is the way in. It holds the grammars that turn written targets such
//! as `192.0.2.0/24` or `[fe80::1%en0]:22` into the values above.
//!
//! # Usable on its own
//!
//! This module depends on nothing else in the crate. Targets parse, address sets do
//! arithmetic, and hosts and ports hold their values without linking anything that
//! scans.
//!
//! Expanding a keyword like `lan`, looking up an interface by name, and resolving a
//! hostname all read the machine the process runs on, so each arrives as a
//! caller-supplied function. An expression that needs a lookup the caller did not
//! provide is refused.
//!
//! These functions return values and never log.
//!
//! # Serialization
//!
//! None of these types are serializable. The document a scan produces is a separate
//! contract, written by hand in [`export::schema`](crate::export::schema), so fields
//! here can move without breaking anyone's parser.

pub mod capture;
pub mod confidence;
pub mod exclusion;
pub mod finding;
pub mod host;
pub mod ip;
pub mod mac;
pub mod order;
pub mod parse;
pub mod port;
pub mod target;
pub mod technique;
pub mod tls;

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ╚════██║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::confidence::Confidence;
    use super::finding::{DetectionClass, Severity};
    use super::host::status::{HostStatus, StatusProtocol};
    use super::host::{Filtering, IpProtocolState, NetworkRole};
    use super::parse::ip::Keyword;
    use super::port::{PortState, Protocol};
    use super::technique::TcpScanTechnique;

    /// Holds one vocabulary's `ALL` to the order its enum declares.
    ///
    /// A fieldless enum's variant casts to its declaration index, so an entry anywhere
    /// else is out of order, a repeat, or a sign of a missing variant. `index_of` is
    /// that cast, passed in because it needs the concrete type.
    fn holds_declaration_order<T: std::fmt::Debug>(
        vocabulary: &str,
        all: &[T],
        index_of: impl Fn(&T) -> usize,
    ) {
        for (position, value) in all.iter().enumerate() {
            assert_eq!(
                index_of(value),
                position,
                "{vocabulary}::ALL: {value:?} is at {position} and declares itself at {}",
                index_of(value)
            );
        }
    }

    /// Where `value` sits in [`StatusProtocol::ALL`], or `None` for the variant
    /// that is not in it.
    ///
    /// `StatusProtocol` carries a name in one variant, so it cannot be cast to its
    /// index. The match is exhaustive, so a new variant fails to compile here.
    fn status_protocol_index(value: &StatusProtocol) -> Option<usize> {
        match value {
            StatusProtocol::Arp => Some(0),
            StatusProtocol::Ndp => Some(1),
            StatusProtocol::IcmpEcho => Some(2),
            StatusProtocol::IcmpTimestamp => Some(3),
            StatusProtocol::IcmpUnreachable => Some(4),
            StatusProtocol::TcpSyn => Some(5),
            StatusProtocol::TcpConnect => Some(6),
            StatusProtocol::Tcp => Some(7),
            StatusProtocol::Dhcp => Some(8),
            StatusProtocol::Udp => Some(9),
            StatusProtocol::Sctp => Some(10),
            // Named by a strategy, so it has no fixed place.
            StatusProtocol::Custom(_) => None,
        }
    }

    /// Every `ALL` in this module, held to its enum's own order.
    ///
    /// The lists are the module's enumeration contract: the exported schema's enums
    /// are built from them, the wire round trip iterates them, a `FromStr` error
    /// message is composed from one, and a report's role line is ordered by another.
    ///
    /// A variant appended to an enum but not its `ALL` is not caught here, since stable
    /// Rust cannot read a variant count without a derive macro. Instead, every
    /// vocabulary is spelled for the wire in [`record::wire`](crate::record::wire) by
    /// an exhaustive `match`, whose round trip is driven by the `ALL`.
    ///
    /// A vocabulary added to this module belongs below.
    #[test]
    fn every_vocabulary_lists_itself_in_declaration_order() {
        holds_declaration_order("Confidence", Confidence::ALL, |v| *v as usize);
        holds_declaration_order("Keyword", Keyword::ALL, |v| *v as usize);
        holds_declaration_order("Severity", Severity::ALL, |v| *v as usize);
        holds_declaration_order("DetectionClass", DetectionClass::ALL, |v| *v as usize);
        holds_declaration_order("NetworkRole", NetworkRole::ALL, |v| *v as usize);
        holds_declaration_order("Filtering", Filtering::ALL, |v| *v as usize);
        holds_declaration_order("HostStatus", HostStatus::ALL, |v| *v as usize);
        holds_declaration_order("IpProtocolState", IpProtocolState::ALL, |v| *v as usize);
        holds_declaration_order("Protocol", Protocol::ALL, |v| *v as usize);
        holds_declaration_order("PortState", PortState::ALL, |v| *v as usize);
        holds_declaration_order("TcpScanTechnique", TcpScanTechnique::ALL, |v| *v as usize);

        holds_declaration_order("StatusProtocol", StatusProtocol::ALL, |v| {
            status_protocol_index(v).expect("ALL holds no `Custom`")
        });
    }
}
