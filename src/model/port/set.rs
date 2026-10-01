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
//! wrote, such as `"80, 443, 1000-2000, u:53, s:2905"`, held as disjoint ranges
//! per protocol. A qualifier in front of a token names the transport for it and every
//! token after it until the next; the spelling belongs to [`Protocol::spec_prefix`].
//!
//! It is canonical from construction and never mutated, so:
//!
//! - Membership is a binary search over sorted disjoint ranges, taking `&self`, so a
//!   set can be shared across workers without a lock.
//! - `Hash` agrees with `Eq`: two sets holding the same ports have identical range
//!   vectors, which lets
//!   [`TargetMapBuilder`](crate::model::parse::target::TargetMapBuilder) group targets
//!   by port specification in constant time.

use crate::model::port::Protocol;
use std::{
    fmt,
    num::{IntErrorKind, ParseIntError},
    ops::RangeInclusive,
    str::FromStr,
};
use thiserror::Error;

/// The ports [`PortSet::common_discovery`] names: a handful that answer often
/// enough to be worth asking every host about, across Linux, Windows and
/// networking gear.
///
/// SSH, HTTP, HTTPS, SMB and RDP. The unprivileged discovery sweep probes exactly
/// these.
pub const COMMON_DISCOVERY_PORTS: &[u16] = &[22, 80, 443, 445, 3389];

/// Where a range with its start left off begins: `-1024` means `1-1024`.
///
/// One, since port 0 is reserved and nothing listens on it. Name `0` outright to
/// include it.
const FIRST_PORT: u16 = 1;

// ══════════════════════════════════════════════════════════════════════════════
// Error Types
// ══════════════════════════════════════════════════════════════════════════════

/// Errors that can occur when parsing a port range string.
///
/// Each says what was wrong with which token and, in parentheses, what to write
/// instead.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PortSetParseError {
    /// A port was not a number, or was too large to be one. Ports are 16-bit,
    /// so `70000` fails here rather than wrapping to `4464`.
    #[error("{}", invalid_port(input, source))]
    InvalidPort {
        /// The token as written.
        input: String,
        /// Why it did not parse.
        #[source]
        source: ParseIntError,
    },

    /// A range was written backwards, as in `80-20`.
    #[error("range {start}-{end} runs backwards (write {end}-{start})")]
    InvalidRange {
        /// The lower bound as written, which is the larger of the two.
        start: u16,
        /// The upper bound as written.
        end: u16,
    },

    /// The input segment did not match any known port or range format.
    #[error("'{0}' is not a port or a range (write 22 or 1-1024)")]
    MalformedSpec(String),

    /// A range was written with spaces around its dash, as in `80 - 90`.
    ///
    /// Refused, because spaces separate ports: `80 - 90` would read as two open-ended
    /// ranges and a bare dash, which is every port. Carries the range as written.
    #[error("'{0}' has spaces in a range (write {joined})", joined = .0.split_whitespace().collect::<String>())]
    SpacedRange(String),

    /// A name was written where a port number goes, as in `ssh`.
    ///
    /// Carries the token as written, qualifier included. Names are not resolved, so a
    /// specification means the same ports on every build; a front end can suggest the
    /// number from the signature corpus.
    #[error("'{0}' is a name, not a port number (write one, as 22)")]
    ServiceName(String),

    /// A specification that is to name the ports a scan covers named none, as
    /// `""` or `" , "` does.
    ///
    /// Never returned by [`PortSet::try_from`], for which the empty string is the empty
    /// set. Returned where a specification says what to scan (a target's port half, a
    /// scan request's ports, a settings file's default), since an empty set would plan
    /// a scan of nothing.
    #[error("names no ports (write 22 or 1-1024)")]
    NoPorts,
}

/// The message for a token that is not a port number, by why it is not one.
fn invalid_port(input: &str, source: &ParseIntError) -> String {
    match source.kind() {
        IntErrorKind::PosOverflow => format!("'{input}' is not a port (the highest is 65535)"),
        // Only a bare qualifier gets here empty; a missing range end is an open
        // end.
        IntErrorKind::Empty => format!("'{input}' names no port (write {input}53)"),
        _ => format!("'{input}' is not a port number (write 22, 1-1024 or u:53)"),
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// PortSet Core Model
// ══════════════════════════════════════════════════════════════════════════════

/// The ports a scan asks about on each transport, as sorted disjoint ranges.
///
/// Canonical from construction and immutable; see the module documentation.
///
/// Ranges, since specifications are overwhelmingly contiguous (`1-1024`, `1-65535`).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PortSet {
    tcp: Vec<RangeInclusive<u16>>,
    udp: Vec<RangeInclusive<u16>>,
    sctp: Vec<RangeInclusive<u16>>,
}

impl PortSet {
    /// Creates a new, empty `PortSet`.
    pub fn new() -> Self {
        Self {
            tcp: Vec::new(),
            udp: Vec::new(),
            sctp: Vec::new(),
        }
    }

    /// The ports worth asking every host about when the caller named none:
    /// [`COMMON_DISCOVERY_PORTS`].
    ///
    /// An opinion, so not [`Default`]: a caller scanning this set should say so.
    pub fn common_discovery() -> Self {
        COMMON_DISCOVERY_PORTS
            .iter()
            .map(|&port| (port, Protocol::Tcp))
            .collect()
    }

    /// The `count` TCP ports this engine would ask about first.
    ///
    /// The default when the caller named no ports. The first hundred are ranked against
    /// each other and the rest grouped into tiers; see
    /// [`catalog`](crate::model::port::catalog).
    ///
    /// Clamped to what the catalogue holds.
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::port::set::PortSet;
    ///
    /// let top = PortSet::top_tcp(100);
    /// assert!(top.has_tcp(443));
    /// // Outside the well-known range, and common on home servers.
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
    /// Drawn from a much shorter list than [`top_tcp`](Self::top_tcp), since UDP ports
    /// cost more to classify and often stay
    /// [`OpenOrNoReply`](crate::model::port::PortState::OpenOrNoReply).
    pub fn top_udp(count: usize) -> Self {
        super::catalog::top_udp(count)
            .iter()
            .map(|&port| (port, Protocol::Udp))
            .collect()
    }

    /// The `count` SCTP ports this engine would ask about first.
    ///
    /// Not a default: a scan reaches SCTP only where a specification names it. See
    /// [`catalog::SCTP_BY_PREVALENCE`](super::catalog::SCTP_BY_PREVALENCE).
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::port::set::PortSet;
    ///
    /// // The mobile core comes first.
    /// assert!(PortSet::top_sctp(3).has_sctp(3868));
    /// ```
    pub fn top_sctp(count: usize) -> Self {
        super::catalog::top_sctp(count)
            .iter()
            .map(|&port| (port, Protocol::Sctp))
            .collect()
    }

    /// The total number of distinct port and protocol pairs.
    pub fn len(&self) -> usize {
        Protocol::ALL
            .iter()
            .copied()
            .map(|protocol| self.len_on(protocol))
            .sum()
    }

    /// Returns `true` if no ports are defined on any protocol.
    pub fn is_empty(&self) -> bool {
        Protocol::ALL
            .iter()
            .copied()
            .all(|protocol| self.ranges(protocol).is_empty())
    }

    /// Returns an iterator over all individual ports in the set.
    ///
    /// In [`Protocol::ALL`] order, whatever order the set was written in.
    pub fn iter(&self) -> impl Iterator<Item = (u16, Protocol)> + '_ {
        Protocol::ALL.iter().copied().flat_map(move |protocol| {
            self.ranges(protocol)
                .iter()
                .flat_map(move |range| range.clone().map(move |port| (port, protocol)))
        })
    }

    /// Flattens the set into a vector of individual ports.
    pub fn to_vec(&self) -> Vec<(u16, Protocol)> {
        self.iter().collect()
    }

    /// The ports on one transport, as the merged ranges they are stored as.
    ///
    /// Ascending and non-overlapping. A full sweep is one entry here and 65,535 through
    /// [`iter`](Self::iter).
    pub fn ranges(&self, protocol: Protocol) -> &[RangeInclusive<u16>] {
        match protocol {
            Protocol::Tcp => &self.tcp,
            Protocol::Udp => &self.udp,
            Protocol::Sctp => &self.sctp,
        }
    }

    /// The lane a protocol's ranges are built into.
    ///
    /// The one exhaustive match over [`Protocol`] on the write side, so a new transport
    /// fails to compile until its ports have a place.
    fn lane_mut(&mut self, protocol: Protocol) -> &mut Vec<RangeInclusive<u16>> {
        match protocol {
            Protocol::Tcp => &mut self.tcp,
            Protocol::Udp => &mut self.udp,
            Protocol::Sctp => &mut self.sctp,
        }
    }

    /// How many ports the set holds on one transport.
    pub fn len_on(&self, protocol: Protocol) -> usize {
        self.ranges(protocol)
            .iter()
            .map(|range| usize::from(*range.end() - *range.start()) + 1)
            .sum()
    }

    /// The ports in either set.
    ///
    /// Merged as ranges, without expanding them.
    pub fn union(&self, other: &PortSet) -> PortSet {
        let mut merged = PortSet::new();
        for &protocol in Protocol::ALL {
            let lane = merged.lane_mut(protocol);
            lane.extend(self.ranges(protocol).iter().cloned());
            lane.extend(other.ranges(protocol).iter().cloned());
            Self::merge_ranges(lane);
        }
        merged
    }

    /// The ports in this set and not in `other`.
    ///
    /// Cut as ranges, like [`union`](Self::union): one port out of a full sweep leaves
    /// two entries.
    ///
    /// ```
    /// use zond_engine::model::port::set::PortSet;
    ///
    /// let scan = PortSet::try_from("1-1024,9100,u:53").unwrap();
    /// let kept = scan.difference(&PortSet::try_from("22,9100-9107").unwrap());
    /// assert_eq!(kept.to_string(), "1-21,23-1024,u:53");
    /// ```
    pub fn difference(&self, other: &PortSet) -> PortSet {
        let mut kept = PortSet::new();
        for &protocol in Protocol::ALL {
            let cuts = other.ranges(protocol);
            let lane = kept.lane_mut(protocol);
            for range in self.ranges(protocol) {
                // What is left of `range` from here up; `None` once a cut reached
                // its end. Both lists are sorted and disjoint.
                let mut rest = Some(*range.start());
                for cut in cuts {
                    let Some(start) = rest else { break };
                    if *cut.end() < start {
                        continue;
                    }
                    if *cut.start() > *range.end() {
                        break;
                    }
                    if *cut.start() > start {
                        lane.push(start..=*cut.start() - 1);
                    }
                    rest = cut.end().checked_add(1).filter(|next| next <= range.end());
                }
                if let Some(start) = rest {
                    lane.push(start..=*range.end());
                }
            }
        }
        kept
    }

    /// Whether the set holds `port` on `protocol`, by binary search over the ranges.
    pub fn contains(&self, port: u16, protocol: Protocol) -> bool {
        self.ranges(protocol)
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

    /// Whether `port` is in the TCP half of the set.
    pub fn has_tcp(&self, port: u16) -> bool {
        self.contains(port, Protocol::Tcp)
    }

    /// Whether `port` is in the UDP half of the set.
    pub fn has_udp(&self, port: u16) -> bool {
        self.contains(port, Protocol::Udp)
    }

    /// Whether `port` is in the SCTP half of the set.
    pub fn has_sctp(&self, port: u16) -> bool {
        self.contains(port, Protocol::Sctp)
    }

    // ─── Internal Utility ────────────────────────────────────────────────────

    /// Sorts and merges overlapping and adjacent ranges; called during construction.
    fn merge_ranges(ranges: &mut Vec<RangeInclusive<u16>>) {
        if ranges.is_empty() {
            return;
        }

        ranges.sort_by_key(|r| *r.start());
        let mut merged = Vec::with_capacity(ranges.len());
        let mut it = ranges.drain(..);
        let mut current = it.next().unwrap();

        for next in it {
            // Overlapping or adjacent
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
    /// The empty set. The opinionated one is
    /// [`common_discovery`](Self::common_discovery), so a struct deriving `Default`
    /// around a `PortSet` gets no ports nobody wrote.
    fn default() -> Self {
        Self::new()
    }
}

/// The set as a specification [`TryFrom<&str>`](PortSet::try_from) reads back.
///
/// The canonical form: protocols in [`Protocol::ALL`] order, each range ascending
/// behind its own prefix, a single port as itself and a run as `start-end`. TCP comes
/// first with no qualifier; every other range carries its own, so the rendering reads
/// the same whether a parser applies a qualifier to one token or until the next. Two
/// sets holding the same ports render identically.
///
/// An empty set renders as the empty string, and reads back as an empty set.
///
/// ```
/// use zond_engine::model::port::set::PortSet;
///
/// let set = PortSet::try_from("443, 80, 1000-1005, u:53, s:2905").unwrap();
/// assert_eq!(set.to_string(), "80,443,1000-1005,u:53,s:2905");
/// assert_eq!(PortSet::try_from(set.to_string().as_str()).unwrap(), set);
/// ```
impl fmt::Display for PortSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for &protocol in Protocol::ALL {
            for range in self.ranges(protocol) {
                if !first {
                    f.write_str(",")?;
                }
                first = false;
                f.write_str(protocol.spec_prefix())?;
                if range.start() == range.end() {
                    write!(f, "{}", range.start())?;
                } else {
                    write!(f, "{}-{}", range.start(), range.end())?;
                }
            }
        }
        Ok(())
    }
}

/// Splits a written token into the protocol a qualifier in front of it names,
/// if it carries one, and the port or range left behind.
///
/// Case-insensitive: `U:53` is `u:53`. The qualifiers are [`Protocol::qualifier`]'s,
/// including `t:` for switching back to TCP.
fn split_qualifier(word: &str) -> (Option<Protocol>, &str) {
    for &protocol in Protocol::ALL {
        let qualifier = protocol.qualifier();
        if let Some(head) = word.get(..qualifier.len())
            && head.eq_ignore_ascii_case(qualifier)
        {
            return (Some(protocol), &word[qualifier.len()..]);
        }
    }
    (None, word)
}

/// Refuses a range written with spaces around its dash, as in `80 - 90`,
/// `80- 90` or `80 -90`.
///
/// Spaces separate ports, so each arrives as words with an open end facing another word
/// across spaces, which nobody means. An open end facing a comma or the edge of the
/// specification is an ordinary open-ended range, so `80, -1024` and `-1024 8080` work.
fn refuse_spaced_range(words: &[&str]) -> Result<(), PortSetParseError> {
    for (index, word) in words.iter().enumerate() {
        let opens_back = word.starts_with('-') && index > 0;
        let opens_on = word.ends_with('-') && index + 1 < words.len();
        if opens_back || opens_on {
            let first = if opens_back { index - 1 } else { index };
            let last = if opens_on { index + 1 } else { index };
            return Err(PortSetParseError::SpacedRange(
                words[first..=last].join(" "),
            ));
        }
    }
    Ok(())
}

/// Parses one port where a number goes, telling a name written there apart
/// from any other token that is not a number.
///
/// `whole` is the token the number came from, which the error carries, so a UDP port
/// reports `u:http`.
fn port_number(text: &str, whole: &str) -> Result<u16, PortSetParseError> {
    text.parse::<u16>().map_err(|source| {
        let named = text.starts_with(|c: char| c.is_ascii_alphabetic())
            && text
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if named {
            PortSetParseError::ServiceName(whole.to_string())
        } else {
            PortSetParseError::InvalidPort {
                input: whole.to_string(),
                source,
            }
        }
    })
}

impl TryFrom<&str> for PortSet {
    type Error = PortSetParseError;

    /// Parses a string into a canonicalized `PortSet`.
    ///
    /// ### Format Support
    /// * **Individual**: `80`, `443`
    /// * **Ranges**: `1000-2000`
    /// * **Open-ended ranges**: `-1024` is everything up to 1024, `1024-` everything
    ///   from it, and a bare `-` every port. Works for the UDP half (`u:-`) too.
    /// * **Protocols**: TCP until a qualifier says otherwise. `u:` switches to UDP,
    ///   `s:` to SCTP and `t:` back to TCP, and a qualifier holds until the next one:
    ///   `u:53,161` is two UDP ports. Case-insensitive.
    /// * **Separators**: commas and spaces, in any number. A range has no spaces;
    ///   `80 - 90` is refused.
    /// * **Mixed**: `80, 443, 161-162, u:53, s:2905`
    ///
    /// # Examples
    ///
    /// ```
    /// use zond_engine::model::port::set::PortSet;
    ///
    /// let set = PortSet::try_from("80, 1000-1005, u:53,161, s:2905").unwrap();
    /// assert!(set.has_tcp(80) && set.has_tcp(1000));
    /// assert!(set.has_udp(53) && set.has_udp(161));
    /// assert!(set.has_sctp(2905));
    /// assert_eq!(set.len(), 10); // 1 + 6 + 2 + 1
    ///
    /// // Back to TCP after another transport.
    /// assert!(PortSet::try_from("u:53, t:80").unwrap().has_tcp(80));
    ///
    /// // Every port.
    /// let everything = PortSet::try_from("-").unwrap();
    /// assert_eq!(everything.len(), 65_535);
    /// assert!(everything.has_tcp(1) && everything.has_tcp(65_535));
    /// ```
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let mut set = PortSet::new();
        let mut protocol = Protocol::Tcp;

        for part in value.split(',') {
            let words: Vec<&str> = part.split_whitespace().collect();
            refuse_spaced_range(&words)?;

            for word in words {
                let (qualifier, raw_range) = split_qualifier(word);
                if let Some(named) = qualifier {
                    protocol = named;
                }

                let range = match raw_range.split('-').collect::<Vec<_>>().as_slice() {
                    [single] => {
                        let port = port_number(single, word)?;
                        port..=port
                    }
                    // A missing end means "as far as there is"; `-` alone is every
                    // port.
                    [start, end] => {
                        let start = if start.is_empty() {
                            FIRST_PORT
                        } else {
                            port_number(start, start)?
                        };
                        let end = if end.is_empty() {
                            u16::MAX
                        } else {
                            port_number(end, end)?
                        };
                        if start > end {
                            return Err(PortSetParseError::InvalidRange { start, end });
                        }
                        start..=end
                    }
                    _ => return Err(PortSetParseError::MalformedSpec(word.to_string())),
                };

                set.lane_mut(protocol).push(range);
            }
        }

        for &protocol in Protocol::ALL {
            Self::merge_ranges(set.lane_mut(protocol));
        }

        Ok(set)
    }
}

impl PortSet {
    /// Parses a specification that says which ports a scan covers, refusing
    /// one that names none with [`PortSetParseError::NoPorts`].
    pub(crate) fn parse_scan(spec: &str) -> Result<Self, PortSetParseError> {
        let set = Self::try_from(spec)?;
        if set.is_empty() {
            return Err(PortSetParseError::NoPorts);
        }
        Ok(set)
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
        let mut set = PortSet::new();
        for (port, protocol) in iter {
            set.lane_mut(protocol).push(port..=port);
        }
        for &protocol in Protocol::ALL {
            Self::merge_ranges(set.lane_mut(protocol));
        }
        set
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

    /// Taking ports out of a set leaves exactly the rest, per transport.
    ///
    /// Cuts at either end of a range, inside it, spanning two ranges, at 65535, and on
    /// another transport.
    #[test]
    fn a_difference_keeps_every_port_outside_the_cut_and_none_inside_it() {
        let set = |spec: &str| PortSet::try_from(spec).expect("a specification");

        let cases = [
            ("1-100", "1", "2-100"),
            ("1-100", "100", "1-99"),
            ("1-100", "50-60", "1-49,61-100"),
            ("1-10,20-30", "5-25", "1-4,26-30"),
            ("1-65535", "65535", "1-65534"),
            ("1-65535", "1-65535", ""),
            ("80,443", "u:80", "80,443"),
            ("80,u:53,s:2905", "u:53", "80,s:2905"),
            ("9100-9107", "9000-9007,9100-9107", ""),
        ];
        for (from, cut, left) in cases {
            let kept = set(from).difference(&set(cut));
            assert_eq!(kept.to_string(), left, "{from} less {cut}");
            for (port, protocol) in set(from).iter() {
                assert_eq!(
                    kept.contains(port, protocol),
                    !set(cut).contains(port, protocol),
                    "{from} less {cut}, at {port}/{protocol:?}"
                );
            }
        }
    }

    /// Three transports in one specification, each behind its own prefix, and
    /// the rendering reads back as what was written.
    #[test]
    fn a_specification_keeps_its_three_transports_apart() {
        let set = PortSet::try_from("80, u:53, S:2905-2906").expect("a mixed specification");

        assert!(set.has_tcp(80) && !set.has_sctp(80));
        assert!(set.has_udp(53) && !set.has_sctp(53));
        assert!(set.has_sctp(2905) && set.has_sctp(2906) && !set.has_udp(2905));
        assert_eq!(set.len_on(Protocol::Sctp), 2);

        assert_eq!(set.to_string(), "80,u:53,s:2905-2906");
        assert_eq!(PortSet::try_from(set.to_string().as_str()).unwrap(), set);
    }

    /// The UDP prefix is case-insensitive, and the error carries the whole token,
    /// prefix included.
    #[test]
    fn the_udp_prefix_is_read_the_way_every_other_token_is() {
        let lower = PortSet::try_from("u:53").expect("the spelling that always worked");
        let upper = PortSet::try_from("U:53").expect("and the one that did not");
        assert_eq!(lower, upper);
        assert!(upper.has_udp(53) && !upper.has_tcp(53));

        // It does not reach back to a TCP port written before it.
        let mixed = PortSet::try_from("80, U:53, u:161-162").expect("parses");
        assert!(mixed.has_tcp(80));
        assert!(mixed.has_udp(53) && mixed.has_udp(161) && mixed.has_udp(162));
        assert!(!mixed.has_tcp(53));

        let error = PortSet::try_from("U:http")
            .expect_err("not a port")
            .to_string();
        assert!(error.contains("U:http"), "the token as written: {error}");
    }

    /// The common forms, mixed in one specification.
    #[test]
    fn a_specification_may_mix_ports_ranges_and_protocols() {
        let port_set_single = PortSet::try_from("21");
        let port_set_multiple = PortSet::try_from("21, 22 80, 800-1000, u:53 t:8080");

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

    /// `u:` applies to a range as well as a single port.
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

    /// Open-ended ranges in all three forms.
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

    /// An open-ended range starts at 1; naming 0 outright still works.
    #[test]
    fn an_open_ended_range_starts_at_one_and_zero_must_be_asked_for() {
        assert!(!PortSet::try_from("-").unwrap().has_tcp(0));
        assert!(PortSet::try_from("0-").unwrap().has_tcp(0));
        assert!(PortSet::try_from("0").unwrap().has_tcp(0));
    }

    /// Open ends compose with qualifiers and mixed specifications.
    #[test]
    fn an_open_ended_range_composes_with_the_rest_of_the_grammar() {
        let mixed = PortSet::try_from("22, u:-, t:9000-").unwrap();

        assert!(mixed.has_tcp(22));
        assert!(mixed.has_tcp(9000) && mixed.has_tcp(65_535));
        assert!(!mixed.has_tcp(8999));
        assert!(mixed.has_udp(1) && mixed.has_udp(65_535));
    }

    /// Two dashes are refused.
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

    /// Whitespace parses as the empty set, but `parse_scan` refuses it.
    #[test]
    fn a_specification_naming_nothing_is_an_empty_set_not_an_error() {
        let empty = PortSet::try_from("   ");
        assert!(empty.is_ok());
        let set = empty.unwrap();
        assert!(set.tcp.is_empty());
        assert!(set.udp.is_empty());

        for nothing in ["", "   ", " , ,"] {
            assert_eq!(
                PortSet::parse_scan(nothing),
                Err(PortSetParseError::NoPorts)
            );
        }
        assert!(PortSet::parse_scan("22").is_ok());
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

    /// Stray and repeated separators are accepted.
    #[test]
    fn stray_separators_are_tolerated_rather_than_refused() {
        let messy = PortSet::try_from(", 80, , 443 ,").unwrap();
        assert!(messy.has_tcp(80));
        assert!(messy.has_tcp(443));
    }

    /// Each mistake gets its own error, and a port too large for 16 bits does not
    /// wrap.
    #[test]
    fn each_malformed_specification_is_refused_with_its_own_reason() {
        let port_set_invalid_port = PortSet::try_from("80 70000 22");
        let port_set_invalid_range = PortSet::try_from("21 8000-80");
        let port_set_malformed_spec = PortSet::try_from("22 60-70-80 8080");
        let port_set_not_numeric = PortSet::try_from("u:53 12ab 80");
        let port_set_named = PortSet::try_from("u:53 abcdef 80");

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
            port_set_named,
            Err(PortSetParseError::ServiceName(_))
        ));

        assert!(matches!(
            port_set_malformed_spec,
            Err(PortSetParseError::MalformedSpec(_))
        ));
    }

    /// A qualifier holds until the next one: `U:53,161,T:21-25,80` is UDP 53 and 161
    /// and TCP 21-25 and 80.
    #[test]
    fn a_qualifier_holds_until_the_next_one_as_nmap_reads_it() {
        let set = PortSet::try_from("U:53,161").expect("an nmap specification");
        assert!(set.has_udp(53) && set.has_udp(161));
        assert!(!set.has_tcp(161), "161 is UDP, as the qualifier said");

        let mixed = PortSet::try_from("8080, u:53,161, T:21-25,80, s:2905").expect("parses");
        assert!(mixed.has_tcp(8080) && mixed.has_tcp(23) && mixed.has_tcp(80));
        assert!(mixed.has_udp(53) && mixed.has_udp(161));
        assert!(!mixed.has_udp(80) && !mixed.has_tcp(161));
        assert!(mixed.has_sctp(2905));
        assert_eq!(mixed.len(), 1 + 2 + 5 + 1 + 1);

        let tcp = PortSet::try_from("t:22").expect("TCP named outright");
        assert!(tcp.has_tcp(22) && tcp.len() == 1);
    }

    /// A range with spaces around its dash is refused, while an open end facing a
    /// comma or the edge is still an open end.
    #[test]
    fn a_range_written_with_spaces_is_refused_rather_than_widened() {
        for (written, fix) in [
            ("80 - 90", "80-90"),
            ("80- 90", "80-90"),
            ("22, 80 -90", "80-90"),
            ("u:80 - 90", "u:80-90"),
        ] {
            let error = PortSet::try_from(written)
                .expect_err("a spaced range")
                .to_string();
            assert!(
                error.contains(&format!("write {fix}")),
                "{written}: {error}"
            );
        }

        let open = PortSet::try_from("80, -1024 9000-, 443").expect("open ends by commas");
        assert!(open.has_tcp(1) && open.has_tcp(65_535) && open.has_tcp(443));
        assert!(PortSet::try_from("-1024 8080").unwrap().has_tcp(8080));
    }

    /// Each refusal says what to write instead.
    #[test]
    fn each_refusal_says_what_to_write_instead() {
        let hint = |written: &str| PortSet::try_from(written).expect_err("refused").to_string();

        let ssh = hint("ssh");
        assert!(
            ssh.contains("'ssh' is a name") && ssh.contains("as 22"),
            "{ssh}"
        );
        let snmp = hint("U:snmp");
        assert!(snmp.contains("'U:snmp' is a name"), "{snmp}");
        let stray = hint("8o");
        assert!(
            stray.contains("'8o'") && stray.contains("write 22"),
            "{stray}"
        );
        let large = hint("70000");
        assert!(large.contains("65535"), "{large}");
        let backwards = hint("80-20");
        assert!(backwards.contains("write 20-80"), "{backwards}");
        let bare = hint("u:");
        assert!(bare.contains("write u:53"), "{bare}");
        let dashes = hint("1-2-3");
        assert!(
            dashes.contains("'1-2-3'") && dashes.contains("write"),
            "{dashes}"
        );
    }

    /// The owned-string conversion agrees with the borrowed one.
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

    /// `common_discovery` holds exactly [`COMMON_DISCOVERY_PORTS`], and `Default` is
    /// empty.
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

    /// Overlapping, adjacent and subsumed ranges all collapse at construction.
    #[test]
    fn overlapping_and_adjacent_ranges_collapse_on_construction() {
        // Overlap: 1-10 and 5-15 become 1-15
        let set = PortSet::try_from("1-10, 5-15").unwrap();
        assert_eq!(set.len(), 15);
        assert_eq!(set.tcp.len(), 1);

        // Adjacency: 20 and 21 become 20-21
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
        /// Any single port parsed is contained in the set.
        #[test]
        fn single_port_roundtrip(p in 0..=65535u16) {
            let s = format!("{}", p);
            let set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_tcp(p));
            prop_assert_eq!(set.len(), 1);
        }

        /// Any port range `[a, b]` contains all values within it.
        #[test]
        fn port_range_invariant(a in 0..=65535u16, b in 0..=65535u16) {
            let (start, end) = if a < b { (a, b) } else { (b, a) };
            let s = format!("{}-{}", start, end);
            let set = PortSet::from_str(&s).unwrap();

            prop_assert!(set.has_tcp(start));
            prop_assert!(set.has_tcp(end));
            prop_assert_eq!(set.len(), (end - start + 1) as usize);
        }

        /// The `u:` prefix assigns ports to UDP.
        #[test]
        fn udp_prefix_honored(p in 0..=65535u16) {
            let s = format!("u:{}", p);
            let set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_udp(p));
            prop_assert!(!set.has_tcp(p));
        }

        /// Comma-separated lists aggregate their ports.
        #[test]
        fn multiple_ports_aggregation(p1 in 0..=1000u16, p2 in 2000..=3000u16) {
            let s = format!("{}, {}", p1, p2);
            let set = PortSet::from_str(&s).unwrap();
            prop_assert!(set.has_tcp(p1));
            prop_assert!(set.has_tcp(p2));
            prop_assert_eq!(set.len(), 2);
        }

        /// Normalization produces the same port count as a `HashSet`.
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
