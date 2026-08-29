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

use std::collections::hash_map::Entry;
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

/// Groups records from any number of sources into one entry per host.
///
/// The N-way form of the question [`components`] answers for two. Records are
/// given flattened, in whatever order the caller wants them folded, and come
/// back as groups of indices into that list: ascending within a group, and the
/// groups ascending by their lowest index, so the same input always groups the
/// same way.
///
/// **Not the same question as [`components`], and deliberately not the same
/// code.** A comparison asks which of tonight's records *continues* which of
/// last night's, which is a relation between two sides: two baseline records
/// that share an address stay two records, and `HostDelta::is_regrouped` reports
/// that the scans disagreed. This asks which records *are* one host, which is an
/// equivalence over all of them at once, and two records sharing an address are
/// one host whichever documents they came from. Sharing an implementation would
/// force one of the two to answer the other's question.
///
/// The tokens, the identity policy and the link-local zone rule are shared, and
/// those are the parts that carry the argument.
pub(crate) fn groups(records: &[&Host], identity: HostIdentity) -> Vec<Vec<usize>> {
    let mut sets = DisjointSet::new(records.len());
    let mut first_holder: HashMap<Token, usize> = HashMap::new();

    for (i, host) in records.iter().enumerate() {
        for token in tokens(host, identity) {
            match first_holder.entry(token) {
                Entry::Occupied(held) => sets.union(*held.get(), i),
                Entry::Vacant(slot) => {
                    slot.insert(i);
                }
            }
        }
    }

    // Keyed by root, then flattened in first-appearance order, which is the
    // order the roots were minted in and therefore ascending by lowest member.
    let mut grouped: HashMap<usize, Vec<usize>> = HashMap::new();
    let mut order: Vec<usize> = Vec::new();
    for i in 0..records.len() {
        let root = sets.find(i);
        grouped.entry(root).or_insert_with(|| {
            order.push(root);
            Vec::new()
        });
        grouped.get_mut(&root).expect("just inserted").push(i);
    }

    order
        .into_iter()
        .map(|root| grouped.remove(&root).expect("a root that was recorded"))
        .collect()
}

/// Union-find over record indices, by size with path compression.
struct DisjointSet {
    parent: Vec<usize>,
    size: Vec<usize>,
}

impl DisjointSet {
    fn new(len: usize) -> Self {
        Self {
            parent: (0..len).collect(),
            size: vec![1; len],
        }
    }

    fn find(&mut self, mut i: usize) -> usize {
        while self.parent[i] != i {
            self.parent[i] = self.parent[self.parent[i]];
            i = self.parent[i];
        }
        i
    }

    fn union(&mut self, a: usize, b: usize) {
        let (mut a, mut b) = (self.find(a), self.find(b));
        if a == b {
            return;
        }
        if self.size[a] < self.size[b] {
            std::mem::swap(&mut a, &mut b);
        }
        self.parent[b] = a;
        self.size[a] += self.size[b];
    }
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

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗██║  ██║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::model::host::HostStatus;
    use crate::model::ip::scoped::Zone;
    use crate::model::mac::MacAddr;

    fn v4(last: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 0, last))
    }

    fn host(primary: IpAddr) -> Host {
        let mut host = Host::new(primary);
        host.set_status(HostStatus::Up);
        host
    }

    /// Components, sorted so an assertion does not depend on iteration order.
    fn shape(components: &[Component]) -> Vec<(Vec<usize>, Vec<usize>)> {
        let mut out: Vec<(Vec<usize>, Vec<usize>)> = components
            .iter()
            .map(|c| {
                let mut b = c.baseline.clone();
                let mut n = c.current.clone();
                b.sort_unstable();
                n.sort_unstable();
                (b, n)
            })
            .collect();
        out.sort();
        out
    }

    #[test]
    fn a_host_at_the_same_address_pairs_with_itself() {
        let before = [host(v4(1))];
        let after = [host(v4(1))];
        let components = components(
            &before.iter().collect::<Vec<_>>(),
            &after.iter().collect::<Vec<_>>(),
            HostIdentity::AnyAddress,
        );
        assert_eq!(shape(&components), vec![(vec![0], vec![0])]);
    }

    #[test]
    fn hosts_sharing_no_address_do_not_pair() {
        let before = [host(v4(1))];
        let after = [host(v4(2))];
        let components = components(
            &before.iter().collect::<Vec<_>>(),
            &after.iter().collect::<Vec<_>>(),
            HostIdentity::AnyAddress,
        );
        assert_eq!(
            shape(&components),
            vec![(vec![], vec![0]), (vec![0], vec![])],
            "one host went away and another arrived"
        );
    }

    /// The case `AnyAddress` exists for: a machine answering at a second address
    /// in the later scan is one host, not two.
    #[test]
    fn a_shared_secondary_address_pairs_two_records() {
        let mut before = host(v4(1));
        before.add_ip(v4(50));
        let after = host(v4(50));

        let components = components(&[&before], &[&after], HostIdentity::AnyAddress);
        assert_eq!(shape(&components), vec![(vec![0], vec![0])]);
    }

    /// Under `PrimaryAddress` the same pair does not, because only the primary
    /// is a token.
    #[test]
    fn a_shared_secondary_address_does_not_pair_under_primary_address() {
        let mut before = host(v4(1));
        before.add_ip(v4(50));
        let after = host(v4(50));

        let components = components(&[&before], &[&after], HostIdentity::PrimaryAddress);
        assert_eq!(
            shape(&components),
            vec![(vec![], vec![0]), (vec![0], vec![])]
        );
    }

    /// Two records on one side and one on the other is a regrouping, and is
    /// reported as one component rather than resolved by picking a winner.
    #[test]
    fn records_the_two_scans_grouped_differently_form_one_component() {
        let mut merged = host(v4(1));
        merged.add_ip(v4(2));
        let split_a = host(v4(1));
        let split_b = host(v4(2));

        let components = components(&[&merged], &[&split_a, &split_b], HostIdentity::AnyAddress);
        assert_eq!(shape(&components), vec![(vec![0], vec![0, 1])]);
    }

    /// `fe80::1` names a different machine on every segment, so two records on
    /// two interfaces must not fold into one.
    #[test]
    fn link_local_addresses_on_different_zones_are_different_hosts() {
        let link_local = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));

        let mut before = Host::new(link_local);
        before.set_zone(Zone::new(1, "en0"));
        before.set_status(HostStatus::Up);

        let mut after = Host::new(link_local);
        after.set_zone(Zone::new(2, "en1"));
        after.set_status(HostStatus::Up);

        let components = components(&[&before], &[&after], HostIdentity::AnyAddress);
        assert_eq!(
            shape(&components),
            vec![(vec![], vec![0]), (vec![0], vec![])],
            "the same link-local address on two segments is two machines"
        );
    }

    #[test]
    fn hardware_identity_pairs_a_host_that_changed_address() {
        let mac = MacAddr::new(0x2c, 0xcf, 0x67, 0xf2, 0x51, 0xe3);

        let mut before = host(v4(1));
        before.record_mac(mac);
        let mut after = host(v4(2));
        after.record_mac(mac);

        let components = components(&[&before], &[&after], HostIdentity::Hardware);
        assert_eq!(
            shape(&components),
            vec![(vec![0], vec![0])],
            "a DHCP lease moving is not a host being replaced"
        );
    }

    #[test]
    fn groups_folds_records_that_share_an_address() {
        let mut one = host(v4(1));
        one.add_ip(v4(9));
        let two = host(v4(9));
        let three = host(v4(3));

        let mut groups = groups(&[&one, &two, &three], HostIdentity::AnyAddress);
        for group in &mut groups {
            group.sort_unstable();
        }
        groups.sort();
        assert_eq!(groups, vec![vec![0, 1], vec![2]]);
    }
}
