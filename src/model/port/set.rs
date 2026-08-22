// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Which ports to ask about
//!
//! [`PortSet`] is the port half of a scan's target specification: what a person
//! wrote, such as `"80, 443, u:53, 1000-2000"`, held as disjoint ranges per
//! protocol.
//!
//! **It is built once and never mutated.** Every construction path merges and
//! sorts before returning, and there is no method that can undo that, so a
//! `PortSet` is canonical from the moment it exists. Two consequences follow,
//! and both are relied on elsewhere:
//!
//! - Membership is a binary search over sorted disjoint ranges, and it takes
//!   `&self`. A set can be shared across every worker in a scan with no lock,
//!   because there is nothing for a lock to protect.
//! - `Hash` agrees with `Eq`. Two sets holding the same ports hold identical
//!   range vectors whatever order or spelling produced them, which is what lets
//!   [`TargetMapBuilder`](crate::model::parse::target::TargetMapBuilder) group
//!   targets by port specification in constant time per target rather than by
//!   scanning the groups it has so far.

use crate::model::port::Protocol;
use std::{num::ParseIntError, ops::RangeInclusive, str::FromStr};
use thiserror::Error;

/// The ports [`PortSet::common_discovery`] names: a handful that answer often
/// enough to be worth asking every host about, across Linux, Windows and
/// networking gear.
///
/// SSH, HTTP, HTTPS, SMB and RDP. Numbers rather than a written specification,
/// so that everything reaching for this list reaches for the same one: the
/// unprivileged discovery sweep probes exactly these, and a second spelling
/// somewhere else is a second list to keep in step.
pub const COMMON_DISCOVERY_PORTS: &[u16] = &[22, 80, 443, 445, 3389];

/// Where a range with its start left off begins: `-1024` means `1-1024`.
///
/// One rather than zero. Port 0 is reserved and nothing listens on it, so
/// including it in an open-ended range would spend a probe per host to
/// re-establish that — and "everything" written as `-` is a specification people
/// reach for precisely when the port count is already enormous. A caller who
/// genuinely wants it can still name `0` outright.
const FIRST_PORT: u16 = 1;

// ══════════════════════════════════════════════════════════════════════════════
// Error Types
// ══════════════════════════════════════════════════════════════════════════════

/// Errors that can occur when parsing a port range string.
#[non_exhaustive]
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PortSetParseError {
    /// A port was not a number, or was too large to be one. Ports are 16-bit,
    /// so `70000` fails here rather than wrapping to `4464`.
    #[error("Failed to parse port from '{input}': {source}")]
    InvalidPort {
        /// The token as written, so a user can find it in what they typed.
        input: String,
        /// Why it did not parse.
        #[source]
        source: ParseIntError,
    },

    /// A range was written backwards, as in `80-20`.
    #[error("Invalid port range: start ({start}) cannot be strictly greater than end ({end})")]
    InvalidRange {
        /// The lower bound as written, which is the larger of the two.
        start: u16,
        /// The upper bound as written.
        end: u16,
    },

    /// The input segment did not match any known port or range format.
    #[error("Malformed port specification, expected a single port or a range: '{0}'")]
    MalformedSpec(String),
}

// ══════════════════════════════════════════════════════════════════════════════
// PortSet Core Model
// ══════════════════════════════════════════════════════════════════════════════

/// The TCP and UDP ports a scan asks about, as sorted disjoint ranges.
///
/// Canonical from construction and immutable afterwards; the module
/// documentation has what that buys and who relies on it.
///
/// Ranges rather than a set of numbers because the specifications people write
/// are overwhelmingly contiguous, such as `1-1024` or `1-65535`, and holding
/// sixty-five thousand `u16`s to represent one of them costs memory per target
/// group, of which a large import has many.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortSet {
    tcp: Vec<RangeInclusive<u16>>,
    udp: Vec<RangeInclusive<u16>>,
}

impl PortSet {
    /// Creates a new, empty `PortSet`.
    pub fn new() -> Self {
        Self {
            tcp: Vec::new(),
            udp: Vec::new(),
        }
    }

    /// The ports worth asking every host about when the caller named none:
    /// [`COMMON_DISCOVERY_PORTS`].
    ///
    /// A deliberate choice rather than a neutral value, which is why it is not
    /// [`Default`]. A caller that scans this set is scanning what this crate
    /// picked, and should have said so.
    ///
    /// Built from the numbers rather than by parsing a written specification.
    /// The round trip was a fallible call on a constant this module owns, so a
    /// typo in the constant was a panic at a consumer's first call rather than
    /// something the compiler could catch.
    pub fn common_discovery() -> Self {
        COMMON_DISCOVERY_PORTS
            .iter()
            .map(|&port| (port, Protocol::Tcp))
            .collect()
    }

    /// The `count` TCP ports this engine would ask about first.
    ///
    /// The default a scan uses when the caller named no ports, and the answer to
    /// `--top-ports`. See [`catalog`](crate::model::port::catalog) for where the
    /// ranking comes from and how precisely to read it; the short version is
    /// that the first hundred are ranked against each other and the rest are
    /// grouped into tiers of comparable likelihood.
    ///
    /// Clamped to what the catalogue holds, so a caller passing a number a
    /// person typed gets every port there is rather than a panic.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::port::set::PortSet;
    ///
    /// let top = PortSet::top_tcp(100);
    /// assert!(top.has_tcp(443));
    /// // Outside the well-known range, and running a service on a great many
    /// // home servers. This is what `1-1024` was missing.
    /// assert!(PortSet::top_tcp(1000).has_tcp(5432));
    /// ```
    pub fn top_tcp(count: usize) -> Self {
        super::catalog::top_tcp(count)
            .iter()
            .map(|&port| (port, Protocol::Tcp))
            .collect()
    }

    /// The `count` UDP ports this engine would ask about first.
    ///
    /// The counterpart of [`top_tcp`](Self::top_tcp), and deliberately drawn
    /// from a much shorter list: a UDP port costs far more to classify and far
    /// more of them come back
    /// [`OpenFiltered`](crate::model::port::PortState::OpenFiltered) whatever is
    /// done, so the catalogue stops where the extra probes stop buying
    /// certainty.
    pub fn top_udp(count: usize) -> Self {
        super::catalog::top_udp(count)
            .iter()
            .map(|&port| (port, Protocol::Udp))
            .collect()
    }

    /// Returns the total number of unique port/protocol combinations.
    ///
    /// Note: This counts every individual port within every range.
    pub fn len(&self) -> usize {
        let tcp_count: usize = self
            .tcp
            .iter()
            .map(|r| (r.end().saturating_sub(*r.start()) as usize).saturating_add(1))
            .sum();
        let udp_count: usize = self
            .udp
            .iter()
            .map(|r| (r.end().saturating_sub(*r.start()) as usize).saturating_add(1))
            .sum();

        tcp_count + udp_count
    }

    /// Returns `true` if no ports are defined for either protocol.
    pub fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty()
    }

    /// Returns an iterator over all individual ports in the set.
    ///
    /// Yields TCP ports first, followed by UDP ports.
    pub fn iter(&self) -> impl Iterator<Item = (u16, Protocol)> + '_ {
        let tcp_iter = self
            .tcp
            .iter()
            .flat_map(|r| r.clone().map(|p| (p, Protocol::Tcp)));
        let udp_iter = self
            .udp
            .iter()
            .flat_map(|r| r.clone().map(|p| (p, Protocol::Udp)));

        tcp_iter.chain(udp_iter)
    }

    /// Flattens the set into a vector of individual ports.
    pub fn to_vec(&self) -> Vec<(u16, Protocol)> {
        self.iter().collect()
    }

    /// Whether `port` is in the TCP half of the set.
    ///
    /// A binary search over disjoint sorted ranges, which the type is
    /// canonical-by-construction in order to allow.
    pub fn has_tcp(&self, port: u16) -> bool {
        self.tcp
            .binary_search_by(|range| {
                if port < *range.start() {
                    std::cmp::Ordering::Greater
                } else if port > *range.end() {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    /// Whether `port` is in the UDP half of the set. The counterpart of
    /// [`has_tcp`](Self::has_tcp).
    pub fn has_udp(&self, port: u16) -> bool {
        self.udp
            .binary_search_by(|range| {
                if port < *range.start() {
                    std::cmp::Ordering::Greater
                } else if port > *range.end() {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Equal
                }
            })
            .is_ok()
    }

    // ─── Internal Utility ────────────────────────────────────────────────────

    /// Sorts and merges overlapping/adjacent ranges.
    /// Called automatically during construction.
    fn merge_ranges(ranges: &mut Vec<RangeInclusive<u16>>) {
        if ranges.is_empty() {
            return;
        }

        ranges.sort_by_key(|r| *r.start());
        let mut merged = Vec::with_capacity(ranges.len());
        let mut it = ranges.drain(..);
        let mut current = it.next().unwrap();

        for next in it {
            // Check for overlap or adjacency
            if *next.start() <= (*current.end()).saturating_add(1) {
                if *next.end() > *current.end() {
                    current = *current.start()..=*next.end();
                }
            } else {
                merged.push(current);
                current = next;
            }
        }
        merged.push(current);
        *ranges = merged;
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// Conversion Traits
// ══════════════════════════════════════════════════════════════════════════════

impl Default for PortSet {
    /// The empty set, which is what every other `Default` in this crate means
    /// and what a struct deriving `Default` around one has to get.
    ///
    /// The opinionated set is [`common_discovery`](Self::common_discovery). It
    /// was `Default` once, which meant that
    /// [`TargetSet`](crate::model::target::TargetSet) and anything else
    /// deriving `Default` acquired a scan specification nobody wrote.
    fn default() -> Self {
        Self::new()
    }
}

impl TryFrom<&str> for PortSet {
    type Error = PortSetParseError;

    /// Parses a string into a canonicalized `PortSet`.
    ///
    /// ### Format Support
    /// * **Individual**: `80`, `443`
    /// * **Ranges**: `1000-2000`
    /// * **Open-ended ranges**: `-1024` is everything up to 1024, `1024-` is
    ///   everything from it, and a bare `-` is every port there is. The
    ///   convention every scanner's users already have in their fingers, and
    ///   more use than a flag for the same thing would be — it applies to the
    ///   UDP half (`u:-`) and to one side of a mixed specification just as
    ///   readily.
    /// * **Protocols**: Defaults to TCP. Use `u:` prefix for UDP (e.g., `u:53`).
    /// * **Mixed**: `80, 443, u:53, 161-162`
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::port::set::PortSet;
    ///
    /// let set = PortSet::try_from("80, u:53, 1000-1005").unwrap();
    /// assert!(set.has_tcp(80));
    /// assert!(set.has_udp(53));
    /// assert_eq!(set.len(), 8); // 1 + 1 + 6
    ///
    /// // Every port there is, which is what `-p-` means on a command line.
    /// let everything = PortSet::try_from("-").unwrap();
    /// assert_eq!(everything.len(), 65_535);
    /// assert!(everything.has_tcp(1) && everything.has_tcp(65_535));
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();

        for part in value.split([',', ' ']).filter(|s| !s.trim().is_empty()) {
            let part = part.trim();

            let (is_udp, raw_range) = if let Some(stripped) = part.strip_prefix("u:") {
                (true, stripped)
            } else {
                (false, part)
            };

            let parts: Vec<&str> = raw_range.split('-').collect();

            let range = match parts.as_slice() {
                [single_port] => {
                    let p = single_port.parse::<u16>().map_err(|source| {
                        PortSetParseError::InvalidPort {
                            input: single_port.to_string(),
                            source,
                        }
                    })?;
                    p..=p
                }
                // An end left off means "as far as there is", at whichever end
                // it was left off. `-` on its own is both, and so is every port.
                [start_str, end_str] => {
                    let start = if start_str.is_empty() {
                        FIRST_PORT
                    } else {
                        start_str.parse::<u16>().map_err(|source| {
                            PortSetParseError::InvalidPort {
                                input: start_str.to_string(),
                                source,
                            }
                        })?
                    };
                    let end = if end_str.is_empty() {
                        u16::MAX
                    } else {
                        end_str.parse::<u16>().map_err(|source| {
                            PortSetParseError::InvalidPort {
                                input: end_str.to_string(),
                                source,
                            }
                        })?
                    };

                    if start > end {
                        return Err(PortSetParseError::InvalidRange { start, end });
                    }

                    start..=end
                }
                _ => return Err(PortSetParseError::MalformedSpec(raw_range.to_string())),
            };

            if is_udp {
                udp.push(range);
            } else {
                tcp.push(range);
            }
        }

        Self::merge_ranges(&mut tcp);
        Self::merge_ranges(&mut udp);

        Ok(Self { tcp, udp })
    }
}

impl TryFrom<String> for PortSet {
    type Error = PortSetParseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::try_from(value.as_str())
    }
}

impl FromStr for PortSet {
    type Err = PortSetParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl FromIterator<(u16, Protocol)> for PortSet {
    fn from_iter<T: IntoIterator<Item = (u16, Protocol)>>(iter: T) -> Self {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        for (port, proto) in iter {
            // Every arm pushes into a field this struct stores. That is the
            // whole guarantee: a protocol added to `Protocol` stops this
            // compiling until somebody decides where its ports go, where a
            // catch-all - or a local vector nobody returns - would drop them
            // silently and produce a `PortSet` quietly missing what it was given.
            match proto {
                Protocol::Tcp => tcp.push(port..=port),
                Protocol::Udp => udp.push(port..=port),
            }
        }
        Self::merge_ranges(&mut tcp);
        Self::merge_ranges(&mut udp);
        Self { tcp, udp }
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
mod tests {
    use super::*;

    /// The forms a person actually writes, mixed in one specification the way
    /// they arrive on a command line.
    #[test]
    fn a_specification_may_mix_ports_ranges_and_protocols() {
        let port_set_single = PortSet::try_from("21");
        let port_set_multiple = PortSet::try_from("21, 22 80, 800-1000, u:53 8080");

        assert!(port_set_single.is_ok());
        assert!(port_set_multiple.is_ok());

        let port_set_single = port_set_single.unwrap();
        let port_set_multiple = port_set_multiple.unwrap();

        assert!(port_set_single.has_tcp(21));

        assert!(port_set_multiple.has_tcp(21));
        assert!(port_set_multiple.has_tcp(22));
        assert!(port_set_multiple.has_tcp(80));
        assert!(port_set_multiple.has_tcp(900));
        assert!(port_set_multiple.has_udp(53));
        assert!(port_set_multiple.has_tcp(8080));
    }

    /// `u:` is this crate's own spelling for the UDP half, and it has to apply
    /// to a range as well as to a single port.
    #[test]
    fn the_udp_prefix_applies_to_single_ports_and_to_ranges() {
        let port_set_udp = PortSet::try_from("u:22 u:53-100, u:1024");

        assert!(port_set_udp.is_ok());

        let port_set_udp = port_set_udp.unwrap();

        assert!(port_set_udp.has_udp(22));
        assert!(port_set_udp.has_udp(53));
        assert!(port_set_udp.has_udp(80));
        assert!(port_set_udp.has_udp(100));
        assert!(port_set_udp.has_udp(1024));
    }

    /// The spelling every scanner's users already know, in all three of its
    /// forms. `-p-` is the one people type; the open-ended halves fall out of
    /// the same rule and are worth having for their own sake.
    #[test]
    fn a_range_may_leave_off_either_end_or_both() {
        let everything = PortSet::try_from("-").unwrap();
        assert!(everything.has_tcp(1));
        assert!(everything.has_tcp(65_535));
        assert_eq!(everything.len(), 65_535);

        let up_to = PortSet::try_from("-1024").unwrap();
        assert!(up_to.has_tcp(1) && up_to.has_tcp(1024));
        assert!(!up_to.has_tcp(1025));

        let onward = PortSet::try_from("1024-").unwrap();
        assert!(onward.has_tcp(1024) && onward.has_tcp(65_535));
        assert!(!onward.has_tcp(1023));
    }

    /// Port 0 is reserved and nothing listens on it, so an open-ended range
    /// starts at 1 — a probe per host to re-establish that is a probe wasted,
    /// and these are the specifications with the most hosts behind them. Naming
    /// it outright still works.
    #[test]
    fn an_open_ended_range_starts_at_one_and_zero_must_be_asked_for() {
        assert!(!PortSet::try_from("-").unwrap().has_tcp(0));
        assert!(PortSet::try_from("0-").unwrap().has_tcp(0));
        assert!(PortSet::try_from("0").unwrap().has_tcp(0));
    }

    /// The open ends compose with everything else the grammar has: the UDP
    /// prefix, and the other members of a mixed specification.
    #[test]
    fn an_open_ended_range_composes_with_the_rest_of_the_grammar() {
        let mixed = PortSet::try_from("22, u:-, 9000-").unwrap();

        assert!(mixed.has_tcp(22));
        assert!(mixed.has_tcp(9000) && mixed.has_tcp(65_535));
        assert!(!mixed.has_tcp(8999));
        assert!(mixed.has_udp(1) && mixed.has_udp(65_535));
    }

    /// A dash is an end left off, not a wildcard: two of them name no range and
    /// are refused rather than read as one.
    #[test]
    fn more_than_one_dash_is_still_malformed() {
        assert!(matches!(
            PortSet::try_from("--"),
            Err(PortSetParseError::MalformedSpec(_))
        ));
        assert!(matches!(
            PortSet::try_from("1-2-3"),
            Err(PortSetParseError::MalformedSpec(_))
        ));
    }

    /// Whitespace names no ports, which is a valid thing to say — a caller
    /// supplying an empty default is not making a mistake, and the empty set is
    /// what `Default` means.
    #[test]
    fn a_specification_naming_nothing_is_an_empty_set_not_an_error() {
        let empty = PortSet::try_from("   ");
        assert!(empty.is_ok());
        let set = empty.unwrap();
        assert!(set.tcp.is_empty());
        assert!(set.udp.is_empty());
    }

    /// The ends of the 16-bit space, where the range arithmetic is one step
    /// from overflowing.
    #[test]
    fn the_ends_of_the_port_space_parse_and_are_held() {
        let limits = PortSet::try_from("0, 65535, u:0-65535").unwrap();
        assert!(limits.has_tcp(0));
        assert!(limits.has_tcp(65535));
        assert!(limits.has_udp(32768));
    }

    /// Target lists are hand-written and pasted together, so stray and repeated
    /// separators are ordinary rather than exceptional. Refusing them would
    /// reject a file over punctuation.
    #[test]
    fn stray_separators_are_tolerated_rather_than_refused() {
        let messy = PortSet::try_from(", 80, , 443 ,").unwrap();
        assert!(messy.has_tcp(80));
        assert!(messy.has_tcp(443));
    }

    /// Each mistake is reported as the kind of mistake it is, because the
    /// error is printed at whoever typed it. A port too large for 16 bits must
    /// not silently wrap to a port they did not ask for.
    #[test]
    fn each_malformed_specification_is_refused_with_its_own_reason() {
        let port_set_invalid_port = PortSet::try_from("80 70000 22");
        let port_set_invalid_range = PortSet::try_from("21 8000-80");
        let port_set_malformed_spec = PortSet::try_from("22 60-70-80 8080");
        let port_set_not_numeric = PortSet::try_from("u:53 abcdef 80");

        assert!(matches!(
            port_set_invalid_port,
            Err(PortSetParseError::InvalidPort { .. })
        ));

        assert!(matches!(
            port_set_invalid_range,
            Err(PortSetParseError::InvalidRange {
                start: 8000,
                end: 80
            })
        ));

        assert!(matches!(
            port_set_not_numeric,
            Err(PortSetParseError::InvalidPort { .. })
        ));

        assert!(matches!(
            port_set_malformed_spec,
            Err(PortSetParseError::MalformedSpec(_))
        ));
    }

    /// The owned-string conversion has to agree with the borrowed one, since
    /// callers reach this type from both an argument and a parsed config.
    #[test]
    fn an_owned_string_parses_the_same_as_a_borrowed_one() {
        let port_set = PortSet::try_from(String::from("21 80-100 u:5353"));

        assert!(port_set.is_ok());

        let port_set = port_set.unwrap();

        assert!(port_set.has_tcp(21));
        assert!(port_set.has_tcp(80));
        assert!(port_set.has_tcp(92));
        assert!(port_set.has_tcp(100));
        assert!(port_set.has_udp(5353));
    }

    /// Two claims, and the second is why the first is written here.
    ///
    /// Two claims, and the second is why the first is written here.
    ///
    /// `common_discovery` is the set every caller that wants this crate's
    /// opinion reaches for, including the unprivileged discovery sweep, so what
    /// it holds has to be exactly what [`COMMON_DISCOVERY_PORTS`] names. A
    /// second list somewhere else was how the sweep and this set could come to
    /// disagree with nothing reporting it.
    ///
    /// And `Default` is empty. It named those same five ports once, which meant
    /// every struct deriving `Default` around a `PortSet` — `TargetSet` among
    /// them — silently carried a scan specification nobody wrote.
    #[test]
    fn the_discovery_set_is_what_the_constant_names_and_default_stays_empty() {
        let set = PortSet::common_discovery();
        for &port in COMMON_DISCOVERY_PORTS {
            assert!(set.has_tcp(port), "{port} is named in the discovery set");
        }
        assert_eq!(
            set.len(),
            COMMON_DISCOVERY_PORTS.len(),
            "and nothing else is"
        );

        assert!(PortSet::default().is_empty());
        assert_eq!(PortSet::default(), PortSet::new());
    }

    /// Canonical from construction: overlapping, adjacent and subsumed ranges
    /// all collapse. That is what makes membership a binary search and what
    /// makes `Hash` agree with `Eq`, so two spellings of one set group together
    /// in `TargetMapBuilder`.
    #[test]
    fn overlapping_and_adjacent_ranges_collapse_on_construction() {
        // Overlap: 1-10 and 5-15 should be 1-15
        let set = PortSet::try_from("1-10, 5-15").unwrap();
        assert_eq!(set.len(), 15);
        assert_eq!(set.tcp.len(), 1);

        // Adjacency: 20 and 21 should be 20-21
        let set = PortSet::try_from("20, 21").unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.tcp.len(), 1);

        // Subsumption: 100-200 and 150
        let set = PortSet::try_from("100-200, 150").unwrap();
        assert_eq!(set.len(), 101);
        assert_eq!(set.tcp.len(), 1);

        // Mixed messy overlaps
        let set = PortSet::try_from("u:53, u:53-53, u:50-60, u:55-65").unwrap();
        assert_eq!(set.len(), 16); // 50 to 65
        assert_eq!(set.udp.len(), 1);
    }
}

#[cfg(test)]
mod property_tests {
    use super::*;
    use proptest::prelude::*;

    proptest::proptest! {
        /// Verify that any single port inserted is correctly contained in the set.
        #[test]
        fn single_port_roundtrip(p in 0..=65535u16) {
            let s = format!("{}", p);
            let set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_tcp(p));
            prop_assert_eq!(set.len(), 1);
        }

        /// Verify that any port range [a, b] contains all values within it.
        #[test]
        fn port_range_invariant(a in 0..=65535u16, b in 0..=65535u16) {
            let (start, end) = if a < b { (a, b) } else { (b, a) };
            let s = format!("{}-{}", start, end);
            let set = PortSet::from_str(&s).unwrap();

            prop_assert!(set.has_tcp(start));
            prop_assert!(set.has_tcp(end));
            prop_assert_eq!(set.len(), (end - start + 1) as usize);
        }

        /// Verify that UDP prefix 'u:' correctly assigns ports to the UDP set.
        #[test]
        fn udp_prefix_honored(p in 0..=65535u16) {
            let s = format!("u:{}", p);
            let set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_udp(p));
            prop_assert!(!set.has_tcp(p));
        }

        /// Verify that comma-separated lists correctly aggregate multiple ports.
        #[test]
        fn multiple_ports_aggregation(p1 in 0..=1000u16, p2 in 2000..=3000u16) {
            let s = format!("{}, {}", p1, p2);
            let set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_tcp(p1));
            prop_assert!(set.has_tcp(p2));
            prop_assert_eq!(set.len(), 2);
        }

        /// Invariant: Normalization produces the same port count as a HashSet.
        #[test]
        fn normalization_invariant(ports in prop::collection::vec(0..=500u16, 1..=50)) {
            let s = ports.iter().map(|p| p.to_string()).collect::<Vec<_>>().join(",");
            let set = PortSet::from_str(&s).unwrap();

            let unique_count = ports.into_iter().collect::<std::collections::HashSet<_>>().len();
            prop_assert_eq!(set.len(), unique_count);
            prop_assert!(set.tcp.len() <= unique_count);
        }
    }
}
