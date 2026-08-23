// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Deciding which record describes which host
//!
//! Ports pair by number and transport, which is exact. Hosts do not: a machine
//! can change address between two scans, answer at one address in one scan and
//! another in the next, or be seen as one record by a privileged scan and two by
//! an unprivileged one. Something has to decide which of tonight's records
//! continues which of last night's, and getting it wrong invents a host that
//! appeared and one that vanished out of a machine that did neither.
//!
//! ## How the decision is made
//!
//! Each record yields a set of **identity tokens** under the caller's
//! [`HostIdentity`] policy. A baseline record and a current record are linked
//! when they share a token. The links form a bipartite graph, and each connected
//! component of that graph is one host as far as the comparison is concerned.
//!
//! Components rather than pairs, because pairing greedily would have to break
//! ties, and the tie is information. A component with one record on each side is
//! the ordinary case. A component with one record on one side and two on the
//! other says the two scans grouped the same addresses differently, which is a
//! real event and is reported as one rather than resolved by picking a winner.
//!
//! ## Link-local addresses carry their interface
//!
//! `fe80::1` names a different machine on every segment, so an address token for
//! a link-local address includes the zone the record was found on. Without that
//! two hosts on two interfaces would share a token and be folded into one.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::Arc;

use crate::model::host::Host;
use crate::model::mac::MacAddr;

/// What makes two records, in two different scans, the same host.
///
/// The default is [`AnyAddress`](Self::AnyAddress), which is the policy that
/// survives a dual-stack host being keyed under IPv4 one night and IPv6 the
/// next.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HostIdentity {
    /// Two records are the same host when their primary addresses match.
    ///
    /// The strictest policy and the most literal. A host whose primary address
    /// changed reads as one host gone and another arrived, which is the correct
    /// reading when addresses are the identity — an external scan of a public
    /// range, where the address is the asset and the machine behind it is not.
    PrimaryAddress,

    /// Two records are the same host when they share any address.
    ///
    /// Follows a host whose primary address was re-picked between scans, which
    /// happens whenever a better address turns up: a global address displacing a
    /// link-local one, or a dual-stack host answering over the other family
    /// first.
    #[default]
    AnyAddress,

    /// As [`AnyAddress`](Self::AnyAddress), and two records are also the same
    /// host when they share a hardware address.
    ///
    /// Follows a machine across a DHCP lease change on a segment where the scan
    /// reached the link layer. Not the default because a hardware address is not
    /// always the host's own: a router answering ARP on another machine's behalf
    /// lends its address to everything behind it, and under this policy those
    /// records fold into one.
    Hardware,
}

/// One host, as the two scans between them hold it.
///
/// Indices into the baseline and current host lists the comparison was given.
/// Both are ascending. An empty side is a host only the other scan has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Component {
    pub(crate) baseline: Vec<usize>,
    pub(crate) current: Vec<usize>,
}

/// What links two records into one host.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum Token {
    /// An address, with the zone it is valid on where that is what makes it
    /// unambiguous.
    Address(IpAddr, Option<Arc<str>>),
    /// A hardware address the record was seen at.
    Hardware(MacAddr),
}

/// Groups the two host lists into components, ascending by lowest baseline index
/// and then by lowest current index, so the same two reports always compare to
/// the same list.
pub(crate) fn components(
    baseline: &[&Host],
    current: &[&Host],
    identity: HostIdentity,
) -> Vec<Component> {
    let baseline_tokens: Vec<HashSet<Token>> =
        baseline.iter().map(|host| tokens(host, identity)).collect();
    let current_tokens: Vec<HashSet<Token>> =
        current.iter().map(|host| tokens(host, identity)).collect();

    let baseline_index = index(&baseline_tokens);
    let current_index = index(&current_tokens);

    let mut baseline_seen = vec![false; baseline.len()];
    let mut current_seen = vec![false; current.len()];
    let mut components = Vec::new();

    for start in 0..baseline.len() {
        if baseline_seen[start] {
            continue;
        }
        baseline_seen[start] = true;

        let mut component = Component {
            baseline: Vec::new(),
            current: Vec::new(),
        };
        let mut baseline_queue = vec![start];
        let mut current_queue: Vec<usize> = Vec::new();

        // Alternating flood fill across the two sides. A record is queued at
        // most once, so this walks each token list once overall.
        while !baseline_queue.is_empty() || !current_queue.is_empty() {
            while let Some(i) = baseline_queue.pop() {
                component.baseline.push(i);
                for token in &baseline_tokens[i] {
                    for &j in current_index.get(token).into_iter().flatten() {
                        if !current_seen[j] {
                            current_seen[j] = true;
                            current_queue.push(j);
                        }
                    }
                }
            }

            while let Some(j) = current_queue.pop() {
                component.current.push(j);
                for token in &current_tokens[j] {
                    for &i in baseline_index.get(token).into_iter().flatten() {
                        if !baseline_seen[i] {
                            baseline_seen[i] = true;
                            baseline_queue.push(i);
                        }
                    }
                }
            }
        }

        component.baseline.sort_unstable();
        component.current.sort_unstable();
        components.push(component);
    }

    // Whatever the flood fill never reached is a host only the current scan
    // holds.
    for (j, seen) in current_seen.iter().enumerate() {
        if !seen {
            components.push(Component {
                baseline: Vec::new(),
                current: vec![j],
            });
        }
    }

    components.sort_by_key(|component| {
        (
            component.baseline.first().copied().unwrap_or(usize::MAX),
            component.current.first().copied().unwrap_or(usize::MAX),
        )
    });
    components
}

/// The tokens a record is linked by under `identity`.
fn tokens(host: &Host, identity: HostIdentity) -> HashSet<Token> {
    let zone = host.zone().map(|zone| Arc::from(zone.name()));

    let mut tokens: HashSet<Token> = match identity {
        HostIdentity::PrimaryAddress => {
            let ip = host.primary_ip();
            HashSet::from([Token::Address(ip, scope_of(&ip, &zone))])
        }
        HostIdentity::AnyAddress | HostIdentity::Hardware => host
            .ips()
            .iter()
            .map(|ip| Token::Address(*ip, scope_of(ip, &zone)))
            .collect(),
    };

    if identity == HostIdentity::Hardware
        && let Some(hardware) = host.hardware()
    {
        tokens.extend(hardware.macs().keys().copied().map(Token::Hardware));
    }

    tokens
}

/// The zone that disambiguates `ip`, which is only link-local addresses. A
/// global address means the same machine on every interface, so scoping one
/// would split a host that answered over two of them.
fn scope_of(ip: &IpAddr, zone: &Option<Arc<str>>) -> Option<Arc<str>> {
    is_link_local(ip).then(|| zone.clone()).flatten()
}

/// Whether an address is only meaningful on one link.
fn is_link_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Which records carry each token.
fn index(tokens: &[HashSet<Token>]) -> HashMap<&Token, Vec<usize>> {
    let mut index: HashMap<&Token, Vec<usize>> = HashMap::new();
    for (i, set) in tokens.iter().enumerate() {
        for token in set {
            index.entry(token).or_default().push(i);
        }
    }
    index
}
