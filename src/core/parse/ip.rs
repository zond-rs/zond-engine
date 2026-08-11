// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Network Target Parser
//!
//! This module provides the logic to resolve abstract input strings into a concrete,
//! deduplicated [`IpSet`]. It acts as the translation layer between user intent
//! (CLI arguments, configuration strings) and the underlying network models.
//!
//! ## Supported Formats
//!
//! The parser recognizes several distinct IPv4 formats:
//!
//! * **Single IP**: Standard dotted-decimal notation (e.g., `127.0.0.1`).
//! * **CIDR Block**: Network address with a prefix length (e.g., `192.168.1.0/24`).
//! * **Explicit Range**: Two full IPs separated by a hyphen (e.g., `10.0.0.1-10.0.0.50`).
//! * **Shortened Range**: An IP followed by a hyphen and a partial suffix (e.g., `10.0.0.1-50` or `192.168.1.1-2.254`).
//! * **Keywords**: Special identifiers like `lan`, which resolve dynamically based on the host's active interface.
//!
//! ## Merging Behavior
//!
//! All inputs are resolved into an [`IpSet`]. The parser ensures that overlapping
//! or adjacent inputs are merged into contiguous ranges to optimize scanning performance.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::AtomicBool;
use thiserror::Error;

use crate::core::models::ip::range::{IpError, IpRange, Ipv4Range};
use crate::core::models::ip::set::IpSet;
use crate::success;

/// Global indicator set to `true` if a "lan" resolution was successfully performed.
pub static IS_LAN_SCAN: AtomicBool = AtomicBool::new(false);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Keyword {
    Lan,
    Vpn,
}

impl Keyword {
    pub fn as_str(&self) -> &'static str {
        match self {
            Keyword::Lan => "lan",
            Keyword::Vpn => "vpn",
        }
    }
}

/// Errors encountered during the parsing or resolution of IP-related strings.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IpParseError {
    /// The provided CIDR prefix is outside the valid IPv4 range of 0-32.
    #[error("Invalid CIDR prefix: {0} (must be 0-32)")]
    InvalidPrefix(u8),

    /// The start address of a range is numerically higher than the end address.
    #[error("Invalid range: start address {0} is greater than end address {1}")]
    InvalidRange(IpAddr, IpAddr),

    /// The input string does not match any known IP, Range, or CIDR format.
    #[error("Malformed IP or range string: '{0}'")]
    Malformed(String),

    /// Failed to retrieve local interface information for "lan" resolution.
    #[error("Could not resolve LAN interface: {0}")]
    LanError(String),

    /// Wrapper for underlying network library or calculation failures.
    #[error("Network error: {0}")]
    NetworkError(String),

    /// The provided input resulted in zero valid IP addresses.
    #[error("Target input resulted in an empty set")]
    EmptySet,

    /// An `%interface` suffix was written on a target that cannot use one.
    #[error("'{0}': only a link-local address is scoped to an interface")]
    ZoneOnUnscopedTarget(String),

    /// An `%interface` suffix named an interface this host does not have, or
    /// none could be looked up at all.
    #[error("No interface named '{0}'")]
    UnknownInterface(String),
}

/// Resolves a collection of input strings into a consolidated [`IpSet`].
///
/// Handles whitespace trimming, comma-separated lists, and individual item parsing.
///
/// # Arguments
///
/// * `ips` - A slice of string-like objects representing scan targets.
///
/// # Errors
///
/// Returns an [`IpParseError`] if any component fails to parse or if the final set
/// is empty.
///
/// # Examples
///
/// ```
/// use zond_engine::core::parse::ip::{to_set, Keyword};
/// use zond_engine::core::models::ip::set::IpSet;
///
/// let ips = vec!["192.168.1.0/24", "10.0.0.1", "10.0.0.5-10"];
/// let set = to_set(&ips, None).unwrap();
///
/// // /24 (256) + single (1) + range 5-10 (6) = 263
/// assert_eq!(set.len(), 263);
/// ```
pub type ResolverFn = fn(Keyword, &mut IpSet) -> Result<(), IpParseError>;

/// Looks up an interface by name and returns its scope id.
///
/// Injected for the same reason [`ResolverFn`] is: resolving a name means
/// reading the host's interface list, and this module deliberately knows nothing
/// about the host it runs on. `None` for a name no interface answers to.
pub type ZoneResolverFn = fn(&str) -> Option<u32>;

pub fn to_set<S>(ips: &[S], resolver: Option<ResolverFn>) -> Result<IpSet, IpParseError>
where
    S: AsRef<str>,
{
    to_set_with(ips, resolver, None)
}

/// [`to_set`], additionally able to resolve the `%interface` suffix on a
/// link-local address.
///
/// Separate rather than an extra argument to [`to_set`] so existing callers keep
/// compiling. A caller that does not supply `zones` cannot express a link-local
/// target at all, and gets an error saying so rather than a target set that
/// silently means a different segment.
pub fn to_set_with<S>(
    ips: &[S],
    resolver: Option<ResolverFn>,
    zones: Option<ZoneResolverFn>,
) -> Result<IpSet, IpParseError>
where
    S: AsRef<str>,
{
    let mut set = IpSet::new();

    for ip in ips {
        let s = ip.as_ref().trim();
        if s.is_empty() {
            continue;
        }

        for part in s.split(',').map(|p| p.trim()).filter(|p| !p.is_empty()) {
            insert_expression(part, &mut set, resolver, zones)?;
        }
    }

    if set.is_empty() {
        return Err(IpParseError::EmptySet);
    }

    let len = set.len();
    let suffix = if len == 1 { "" } else { "es" };
    success!("{len} IP address{suffix} resolved successfully");

    Ok(set)
}

/// Identifies the format of a single address expression and inserts it into an
/// existing set.
///
/// This is the grammar itself, without the list handling and the summary line
/// [`to_set_with`] wraps around it. A caller that has already tokenized its
/// input - an importer reading a file of targets, say - wants exactly this: one
/// expression, inserted into a set it is accumulating, and no log line per
/// token to show for it.
///
/// Nothing is inserted when the expression is refused, so a caller that collects
/// errors and carries on is left with a set holding only what parsed.
///
/// [`IpParseError::Malformed`] is the one error worth treating as a question
/// rather than an answer: it means the expression matches no address, range or
/// CIDR form, which is also what a hostname looks like from here. A caller that
/// accepts hostnames uses it as the signal to try resolving one. Every other
/// error describes an address that is wrong rather than absent.
pub fn insert_expression(
    s: &str,
    set: &mut IpSet,
    resolver: Option<ResolverFn>,
    zones: Option<ZoneResolverFn>,
) -> Result<(), IpParseError> {
    // The interface suffix is stripped first and applied to whatever the rest
    // parses to, so `fe80::1%en0` and `fe80::1-fe80::5%en0` are both expressible
    // and mean the obvious thing.
    if let Some((address, zone)) = s.split_once('%') {
        return parse_scoped(s, address, zone, set, zones);
    }

    if s.contains('/') {
        let range = parse_cidr(s)?;
        set.insert_range(range);
        return Ok(());
    }

    if s.contains('-') {
        let range = parse_range(s)?;
        set.insert_range(range);
        return Ok(());
    }

    if s.eq_ignore_ascii_case(Keyword::Lan.as_str()) {
        if let Some(r) = resolver {
            return r(Keyword::Lan, set);
        } else {
            return Err(IpParseError::LanError(
                "LAN keyword used but no resolver provided".into(),
            ));
        }
    }

    let ip = s
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.to_string()))?;
    set.insert(ip);

    Ok(())
}

/// Parses a target carrying an explicit `%interface` suffix.
///
/// The suffix is only meaningful on a link-local address, and only resolvable by
/// a caller that supplied a lookup. Both failures are reported rather than
/// papered over: an interface nobody recognizes and a zone written on an address
/// with no use for one are each a target that does not mean what it says.
fn parse_scoped(
    original: &str,
    address: &str,
    zone: &str,
    set: &mut IpSet,
    zones: Option<ZoneResolverFn>,
) -> Result<(), IpParseError> {
    if zone.is_empty() {
        return Err(IpParseError::Malformed(original.to_string()));
    }

    let range = address
        .parse::<IpRange>()
        .map_err(|_| IpParseError::Malformed(original.to_string()))?;
    let IpRange::V6(v6) = range else {
        return Err(IpParseError::ZoneOnUnscopedTarget(original.to_string()));
    };
    if !v6.start_addr.is_unicast_link_local() {
        return Err(IpParseError::ZoneOnUnscopedTarget(original.to_string()));
    }

    let lookup = zones.ok_or_else(|| IpParseError::UnknownInterface(zone.to_string()))?;
    let index = lookup(zone).ok_or_else(|| IpParseError::UnknownInterface(zone.to_string()))?;

    let scoped =
        crate::core::models::ip::range::Ipv6Range::scoped(v6.start_addr, v6.end_addr, Some(index))
            .map_err(map_range_error)?;
    set.insert_range(IpRange::V6(scoped));
    Ok(())
}

/// Parses hyphenated range strings into an [`IpRange`].
fn parse_range(s: &str) -> Result<IpRange, IpParseError> {
    let (start_str, end_str) = s
        .split_once('-')
        .ok_or_else(|| IpParseError::Malformed(s.into()))?;

    let start_addr = start_str
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    match start_addr {
        IpAddr::V4(start_v4) => {
            let end_v4 = if let Ok(addr) = end_str.parse::<Ipv4Addr>() {
                addr
            } else {
                let mut octets = start_v4.octets();
                let parts: Vec<u8> = end_str
                    .split('.')
                    .map(|p| p.parse::<u8>())
                    .collect::<Result<Vec<u8>, _>>()
                    .map_err(|_| IpParseError::Malformed(s.into()))?;

                if parts.is_empty() || parts.len() > 4 {
                    return Err(IpParseError::Malformed(s.into()));
                }

                let offset = 4 - parts.len();
                octets[offset..].copy_from_slice(&parts);
                Ipv4Addr::from(octets)
            };
            Ipv4Range::new(start_v4, end_v4)
                .map(IpRange::V4)
                .map_err(map_range_error)
        }
        IpAddr::V6(start_v6) => {
            let end_v6 = end_str
                .parse::<Ipv6Addr>()
                .map_err(|_| IpParseError::Malformed(s.into()))?;
            crate::core::models::ip::range::Ipv6Range::new(start_v6, end_v6)
                .map(IpRange::V6)
                .map_err(map_range_error)
        }
    }
}

/// Parses CIDR notation strings into an [`IpRange`].
fn parse_cidr(s: &str) -> Result<IpRange, IpParseError> {
    let (ip_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| IpParseError::Malformed(s.into()))?;

    let ip = ip_str
        .parse::<IpAddr>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| IpParseError::Malformed(s.into()))?;

    crate::core::models::ip::range::cidr_range(ip, prefix).map_err(map_range_error)
}

fn map_range_error(e: IpError) -> IpParseError {
    match e {
        IpError::InvalidRange(s, e) => IpParseError::InvalidRange(s, e),
        IpError::InvalidPrefix(p) => IpParseError::InvalidPrefix(p),
        IpError::NetworkError(msg) => IpParseError::NetworkError(msg),
        _ => IpParseError::Malformed("Invalid IP range".into()),
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
    use std::net::Ipv4Addr;

    #[test]
    fn to_set_basic_single() {
        let input = vec!["192.168.1.1"];
        let set = to_set(&input, None).expect("Should parse single IP");
        assert_eq!(set.len(), 1);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
    }

    #[test]
    fn to_set_comma_separated() {
        let input = vec!["10.0.0.1, 10.0.0.2, 10.0.0.5"];
        let set = to_set(&input, None).expect("Should parse comma list");
        assert_eq!(set.len(), 3);
        assert!(set.contains(&IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn parse_cidr_blocks() {
        let input = vec!["172.16.0.0/24"];
        let set = to_set(&input, None).expect("Should parse CIDR");
        assert_eq!(set.len(), 256);
    }

    #[test]
    fn parse_short_range_suffix() {
        let input = vec!["192.168.1.250-2.10"];
        let set = to_set(&input, None).unwrap();
        assert_eq!(set.len(), 17);
    }

    #[test]
    fn error_invalid_cidr() {
        let input = vec!["192.168.1.1/33"];
        let result = to_set(&input, None);
        assert_eq!(result.unwrap_err(), IpParseError::InvalidPrefix(33));
    }

    #[test]
    fn error_invalid_range_order() {
        let input = vec!["10.0.0.10-1"];
        let result = to_set(&input, None);
        assert!(matches!(result, Err(IpParseError::InvalidRange(_, _))));
    }

    /// The interface a link-local target names survives into the target set.
    ///
    /// Without it the address is a question with no answer: every interface
    /// holds an `fe80::/64`, so the scan picks one and probes the wrong segment.
    #[test]
    fn a_link_local_target_keeps_the_interface_it_names() {
        fn zones(name: &str) -> Option<u32> {
            (name == "en0").then_some(7)
        }

        let set = to_set_with(&["fe80::aa%en0"], None, Some(zones)).expect("parses");

        assert_eq!(set.v6().len(), 1);
        assert_eq!(set.v6()[0].zone, Some(7));
        assert!(!set.v6()[0].is_ambiguous());
    }

    /// The same address without an interface is accepted but marked as the
    /// unanswerable question it is, for the classifier to report.
    #[test]
    fn a_link_local_target_without_an_interface_is_ambiguous() {
        let set = to_set(&["fe80::aa"], None).expect("parses");

        assert!(set.v6()[0].is_ambiguous());
    }

    /// An interface nobody recognizes is a target that does not mean what it
    /// says, and is refused rather than silently stripped of its scope.
    #[test]
    fn an_unknown_interface_is_refused() {
        fn zones(_: &str) -> Option<u32> {
            None
        }

        assert!(matches!(
            to_set_with(&["fe80::aa%wlan9"], None, Some(zones)),
            Err(IpParseError::UnknownInterface(_))
        ));
        assert!(
            matches!(
                to_set(&["fe80::aa%en0"], None),
                Err(IpParseError::UnknownInterface(_))
            ),
            "a caller with no lookup cannot express a scoped target and must be told"
        );
    }

    /// A scope on an address that cannot use one is a mistake, not a hint.
    #[test]
    fn a_zone_on_a_global_target_is_refused() {
        fn zones(_: &str) -> Option<u32> {
            Some(7)
        }

        assert!(matches!(
            to_set_with(&["2001:db8::1%en0"], None, Some(zones)),
            Err(IpParseError::ZoneOnUnscopedTarget(_))
        ));
        assert!(matches!(
            to_set_with(&["192.168.1.1%en0"], None, Some(zones)),
            Err(IpParseError::ZoneOnUnscopedTarget(_))
        ));
    }

    #[test]
    fn empty_input_error() {
        let input: Vec<&str> = vec!["", " "];
        let result = to_set(&input, None);
        assert_eq!(result.unwrap_err(), IpParseError::EmptySet);
    }
}
