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
//! [`TargetMap`](target::TargetMap)), and what the capture saw on the way
//! ([`CaptureCounts`](capture::CaptureCounts)).
//!
//! [`parse`] is the way in. It holds the grammars that turn written targets such
//! as `192.168.1.0/24` or `[fe80::1%en0]:22` into the values above.
//!
//! # Usable on its own
//!
//! This module depends on nothing else in the crate. Targets parse, address sets
//! do arithmetic, and hosts and ports hold their values without a scan starting
//! or anything that would start one being linked.
//!
//! Two consequences are worth knowing about.
//!
//! Nothing here resolves anything for itself. Expanding a keyword like `lan`,
//! looking up an interface by name, and resolving a hostname all mean reading
//! the machine the process runs on, so each arrives as a caller-supplied
//! function. An expression that needs a lookup the caller did not provide is
//! refused rather than guessed at.
//!
//! Nothing here writes output. These functions return values and never log,
//! because only the caller knows what it asked for and at what verbosity it
//! wants to hear about it.
//!
//! # Not the wire format
//!
//! None of these types are serializable. The document a scan produces is a
//! separate contract, written by hand in
//! [`export::schema`](crate::export::schema), so that a field moving here stays
//! a private matter instead of breaking somebody's parser.

pub mod capture;
pub mod confidence;
pub mod exclusion;
pub mod finding;
pub mod host;
pub mod ip;
pub mod mac;
pub mod parse;
pub mod port;
pub mod target;
pub mod technique;

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
    use super::host::{Filtering, NetworkRole};
    use super::parse::ip::Keyword;
    use super::port::{PortState, Protocol};
    use super::technique::TcpScanTechnique;

    /// Holds one vocabulary's `ALL` to the order its enum declares.
    ///
    /// A fieldless enum's variant casts to its own declaration index, so an
    /// entry sitting anywhere else is out of order, a repeat, or standing where
    /// a variant that belongs earlier is missing. `index_of` is that cast,
    /// passed in because it needs the concrete type.
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
    /// `StatusProtocol` carries a name in one variant, so it cannot cast to its
    /// own index the way the fieldless vocabularies do and this match stands in
    /// for the cast. Being exhaustive, it is also where adding a variant becomes
    /// a compile error beside the list it has to join.
    fn status_protocol_index(value: &StatusProtocol) -> Option<usize> {
        match value {
            StatusProtocol::Arp => Some(0),
            StatusProtocol::Ndp => Some(1),
            StatusProtocol::IcmpEcho => Some(2),
            StatusProtocol::IcmpUnreachable => Some(3),
            StatusProtocol::TcpSyn => Some(4),
            StatusProtocol::Tcp => Some(5),
            StatusProtocol::Dhcp => Some(6),
            StatusProtocol::Udp => Some(7),
            StatusProtocol::Sctp => Some(8),
            // Named by a strategy rather than by this enum, so there is no fixed
            // place for it and no list it belongs in.
            StatusProtocol::Custom(_) => None,
        }
    }

    /// Every `ALL` in this module, held to its enum's own order.
    ///
    /// The lists are the module's enumeration contract. The exported schema's
    /// enums are built from them, the wire round trip iterates them, a `FromStr`'s
    /// error message is composed from one, and a report's role line is ordered by
    /// another. Nothing checked any of them, and [`PortState::ALL`] transposed two
    /// pairs while its documentation said declaration order.
    ///
    /// What this does not catch is a variant appended to an enum and not to its
    /// `ALL`, since a list that is right as far as it goes looks complete from
    /// here. Catching that needs the variant count, which no stable Rust reads
    /// without a derive macro. What stands in for it is that every vocabulary here
    /// is spelled for the wire in [`record::wire`](crate::record::wire) by an
    /// exhaustive `match`, so a new variant cannot compile without its author
    /// being taken to a function whose round trip is driven by the `ALL` they have
    /// to update.
    ///
    /// A vocabulary added to this module belongs below.
    #[test]
    fn every_vocabulary_lists_itself_in_declaration_order() {
        holds_declaration_order("Confidence", &Confidence::ALL, |v| *v as usize);
        holds_declaration_order("Keyword", &Keyword::ALL, |v| *v as usize);
        holds_declaration_order("Severity", &Severity::ALL, |v| *v as usize);
        holds_declaration_order("DetectionClass", &DetectionClass::ALL, |v| *v as usize);
        holds_declaration_order("NetworkRole", &NetworkRole::ALL, |v| *v as usize);
        holds_declaration_order("Filtering", &Filtering::ALL, |v| *v as usize);
        holds_declaration_order("HostStatus", &HostStatus::ALL, |v| *v as usize);
        holds_declaration_order("Protocol", &Protocol::ALL, |v| *v as usize);
        holds_declaration_order("PortState", &PortState::ALL, |v| *v as usize);
        holds_declaration_order("TcpScanTechnique", &TcpScanTechnique::ALL, |v| *v as usize);

        holds_declaration_order("StatusProtocol", StatusProtocol::ALL, |v| {
            status_protocol_index(v).expect("ALL holds no `Custom`")
        });
    }
}
