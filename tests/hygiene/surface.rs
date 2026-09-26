// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What the public surface may promise
//!
//! Every line of `public-api.txt` is a commitment: a name a front end may build
//! on, and so one this crate cannot change without a breaking release. The
//! rules here keep that list from promising more than the crate means to. Each
//! is checked against the listing rather than the source, because the listing
//! is what a caller actually sees, re-exports and all, and the release checks
//! already hold it to the build.

use std::collections::BTreeMap;
use std::path::Path;

/// The public API listing, as the release checks generate it.
fn listing() -> String {
    std::fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("public-api.txt"))
        .expect("public-api.txt is in the repository")
}

/// A vocabulary's `ALL` exists so a caller can walk an enum it cannot match
/// exhaustively. As a fixed-size array its length would be part of its type,
/// and the variant `#[non_exhaustive]` makes additive would break every caller
/// that named that type: the same break, moved one line over.
#[test]
fn no_public_constant_is_an_array_of_the_crates_own_type() {
    let listing = listing();
    let arrays: Vec<&str> = listing
        .lines()
        .filter(|line| {
            line.starts_with("pub const ")
                && (line.contains(": [zond_engine::") || line.contains(": [Self;"))
        })
        .collect();
    assert!(
        arrays.is_empty(),
        "public constants whose length is part of their type: {arrays:#?}"
    );
    assert!(
        listing.contains("::port::Protocol::ALL: &'static [Self]"),
        "the listing still spells a slice constant the way this check reads it"
    );
}

/// The modules a strategy is built from, which the crate keeps to itself.
///
/// Each holds state whose shape is still moving: the retry ledger, the adaptive
/// deadline, the congestion window, the tally a raw scan keeps of itself, the
/// loop the raw port scanners share. Publishing any of them would make that
/// shape a promise to every front end, and a caller driving a strategy needs
/// none of it: the strategy's constructor takes the settings that tune it.
const INTERNAL: &[&str] = &[
    "zond_engine::scanner::audit",
    "zond_engine::scanner::pacing",
    "zond_engine::scanner::payload",
    "zond_engine::scanner::pool",
    "zond_engine::scanner::strategy::frames",
    "zond_engine::scanner::strategy::icmp_error",
    "zond_engine::scanner::strategy::raw",
    "zond_engine::scanner::strategy::sweep",
    "zond_engine::scanner::strategy::ports::RawPortScan",
    "zond_engine::scanner::strategy::ports::RawProbeScan",
];

/// Making one of these public again is a deliberate act with a cost, and this
/// is where it has to be argued: a line in the listing under any of them fails
/// here before it reaches a release.
#[test]
fn the_machinery_a_strategy_is_built_from_stays_internal() {
    let listing = listing();
    let exposed: Vec<&str> = listing
        .lines()
        .filter(|line| {
            INTERNAL.iter().any(|path| {
                line.match_indices(path).any(|(at, _)| {
                    !line[at + path.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
                })
            })
        })
        .collect();
    assert!(
        exposed.is_empty(),
        "internal machinery in the public API: {exposed:#?}"
    );
}

/// The crates whose types a public signature may name, and why each is there.
///
/// A type from another crate in a signature ties this crate's releases to that
/// one's: its next breaking release is this crate's, whether or not anything
/// here changed. So the list is short and each entry argues for itself. A
/// dependency missing from it is used inside the crate and is its business
/// alone, converted at the boundary into this crate's own types or plain
/// numbers, as the packet library's hardware addresses and protocol numbers
/// are.
const FOREIGN: &[(&str, &str)] = &[
    ("core", "the language"),
    ("alloc", "the language"),
    ("std", "the language"),
    (
        "serde_core",
        "`Serialize` and `Deserialize` on the types that are a document's \
         shape; serde is 1.x and the file formats are what those derives are for",
    ),
    (
        "tokio",
        "the runtime every scan runs on, 1.x with a stability commitment: its \
         channels carry a scan's events and a port scanner's targets, and its \
         `TcpStream` is what the fingerprinter reads",
    ),
];

/// Each path root in a line of the listing, such as `core` in
/// `core::net::IpAddr`, skipping this crate's own.
fn foreign_roots(line: &str) -> impl Iterator<Item = &str> {
    line.match_indices("::").filter_map(move |(at, _)| {
        let head = &line[..at];
        let start = head
            .rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
            .map_or(0, |i| i + 1);
        let root = &head[start..];
        let is_root = start == 0 || !head[..start].ends_with("::");
        (is_root
            && !root.is_empty()
            && root.starts_with(|c: char| c.is_ascii_lowercase())
            && root != "zond_engine")
            .then_some(root)
    })
}

/// A dependency's type reaching a public signature is how a patch release of
/// that dependency becomes a breaking release of this crate, and it happens by
/// accident: a helper made `pub` that took the library's type, a `From` impl
/// written for the `?` operator. Each is caught here before a release pins it.
#[test]
fn no_public_signature_names_a_crate_outside_the_allow_list() {
    let listing = listing();
    // One line per crate is enough to find the rest by.
    let mut unexpected: BTreeMap<&str, &str> = BTreeMap::new();
    for line in listing.lines() {
        for root in foreign_roots(line) {
            if !FOREIGN.iter().any(|(allowed, _)| *allowed == root) {
                unexpected.entry(root).or_insert(line);
            }
        }
    }
    assert!(
        listing.contains("tokio::sync::mpsc"),
        "the listing still spells a foreign path the way this check reads it"
    );
    assert!(
        unexpected.is_empty(),
        "public signatures naming a crate outside the allow-list: {unexpected:#?}"
    );
}

/// The public structs whose fields are all public and which are nonetheless
/// exhaustive, each a type a caller writes out whole.
///
/// Everything else with a public field is `#[non_exhaustive]`, so a field can
/// be added without a breaking release: a caller reads the fields, and builds
/// one through its constructor or its `Default`. These are the exceptions,
/// and each says why a literal naming every field is the point.
const EXHAUSTIVE: &[(&str, &str)] = &[
    (
        "zond_engine::record::",
        "a record is interchange, built by naming every field; see the `record` module",
    ),
    (
        "Parts",
        "mirrors what it rebuilds field for field, so a field added there stops \
         every rebuild until it says what the new one is",
    ),
    (
        "zond_engine::protocols::craft::",
        "a header's fields are the protocol's, fixed by its RFC, and a caller \
         crafting one states the fields it means to get wrong",
    ),
    (
        "zond_engine::diff::change::Change",
        "a value before and after, which is all a change is",
    ),
    ("zond_engine::diff::Change", "the same type, re-exported"),
    (
        "zond_engine::model::capture::Ipv",
        "what one IP header said, field for field, which the header's format \
         fixes; a synthetic transport writes one out for the packet it stands in for",
    ),
    (
        "zond_engine::transport::probe::IpProtocols",
        "one number per address family, and there are two",
    ),
];

/// Adding a field to a struct a caller can build with a literal breaks that
/// caller, so a type expected to grow has to be sealed before the first
/// release that promises it, not after the field it needed arrives.
#[test]
fn every_struct_with_public_fields_can_grow_unless_it_says_why_not() {
    let listing = listing();
    let exhaustive: BTreeMap<&str, ()> = listing
        .lines()
        .filter_map(|line| line.strip_prefix("pub struct "))
        .map(|rest| (rest.split(['<', ' ', '(']).next().unwrap_or(rest), ()))
        .collect();
    let mut open: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.strip_prefix("pub "))
        .filter_map(|rest| rest.split_once(": ").map(|(path, _)| path))
        .filter_map(|path| path.rsplit_once("::").map(|(owner, _)| owner))
        .filter(|owner| exhaustive.contains_key(owner))
        .filter(|owner| {
            !EXHAUSTIVE
                .iter()
                .any(|(pattern, _)| owner.starts_with(pattern) || owner.ends_with(pattern))
        })
        .collect();
    open.dedup();
    assert!(
        exhaustive.contains_key("zond_engine::record::HostRecord"),
        "the listing still spells a struct the way this check reads it"
    );
    assert!(
        open.is_empty(),
        "exhaustive structs with public fields: {open:#?}"
    );
}
