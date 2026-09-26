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

/// The public constants that are arrays on purpose, and why each one's length
/// is part of what it is.
///
/// Everything else is a slice. A constant listing ports, protocols, bounds or
/// characters is a list the crate may lengthen, and as an array its length
/// would be part of its type: every caller that named the type, or bound the
/// value to a variable of it, breaks when the list grows by one.
const FIXED_LENGTH: &[(&str, &str)] = &[
    (
        "zond_engine::format::UTF8_BOM",
        "the three bytes UTF-8 encodes U+FEFF as; another length would be another mark",
    ),
    (
        "zond_engine::protocols::tls::HELLO_RETRY_RANDOM",
        "the value RFC 8446 section 4.1.3 fixes for a 32-byte field, compared with \
         that field whole",
    ),
];

/// A public constant's path and type, for a line that declares one.
fn constant(line: &str) -> Option<(&str, &str)> {
    line.strip_prefix("pub const ")
        .or_else(|| line.strip_prefix("pub static "))
        .filter(|rest| !rest.starts_with("fn ") && !rest.starts_with("unsafe fn "))?
        .split_once(": ")
}

/// Whether a type is a fixed-size array, or a reference to one.
fn is_array(kind: &str) -> bool {
    let kind = kind.trim_start_matches("&'static ").trim_start_matches('&');
    let Some(inner) = kind.strip_prefix('[') else {
        return false;
    };
    let mut depth = 0usize;
    for c in inner.chars() {
        match c {
            '[' | '(' | '<' => depth += 1,
            ']' | ')' | '>' if depth == 0 => return false,
            ']' | ')' | '>' => depth -= 1,
            ';' if depth == 0 => return true,
            _ => {}
        }
    }
    false
}

/// A list the crate may lengthen is a slice, a vocabulary's `ALL` among them:
/// it exists so a caller can walk an enum it cannot match exhaustively, and
/// as an array the variant `#[non_exhaustive]` makes additive would break
/// every caller that named its type, the same break moved one line over.
#[test]
fn no_public_constant_carries_its_length_in_its_type_unless_it_says_why() {
    let listing = listing();
    let arrays: Vec<&str> = listing
        .lines()
        .filter_map(constant)
        .filter(|(_, kind)| is_array(kind))
        .map(|(path, _)| path)
        .collect();

    let unexplained: Vec<&str> = arrays
        .iter()
        .copied()
        .filter(|path| !FIXED_LENGTH.iter().any(|(fixed, _)| fixed == path))
        .collect();
    assert!(
        unexplained.is_empty(),
        "public constants whose length is part of their type: {unexplained:#?}\n\n\
         Make each a slice, or add it to FIXED_LENGTH in tests/hygiene/surface.rs \
         saying why its length is what it is."
    );

    let stale: Vec<&str> = FIXED_LENGTH
        .iter()
        .map(|(path, _)| *path)
        .filter(|path| !arrays.contains(path))
        .collect();
    assert!(
        stale.is_empty(),
        "these are in FIXED_LENGTH but are no longer public arrays: {stale:?}"
    );
    for (path, why) in FIXED_LENGTH {
        assert!(why.len() > 40, "{path}'s reason is too short: {why:?}");
    }

    assert!(
        listing.contains("::port::Protocol::ALL: &'static [Self]"),
        "the listing still spells a slice constant the way this check reads it"
    );
    assert!(is_array("[u16; 8]") && is_array("&'static [[u8; 2]; 3]"));
    assert!(!is_array("&'static [u16]") && !is_array("&'static [[u8; 2]]"));
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

/// Whether a line of the listing opens an item of its own, which ends the
/// lines describing the struct before it.
fn opens_an_item(line: &str) -> bool {
    let line = line.strip_prefix("#[non_exhaustive] ").unwrap_or(line);
    ["struct ", "enum ", "mod ", "trait ", "union "]
        .iter()
        .any(|kind| {
            line.strip_prefix("pub ")
                .is_some_and(|rest| rest.starts_with(kind))
        })
}

/// Whether a line of the listing is a function, method or constructor.
fn is_function(line: &str) -> bool {
    let mut rest = line.strip_prefix("pub ").unwrap_or("");
    for qualifier in ["const ", "async ", "unsafe "] {
        rest = rest.strip_prefix(qualifier).unwrap_or(rest);
    }
    rest.starts_with("fn ")
}

/// A function line's parameter list and whatever follows it.
fn parameters_and_return(line: &str) -> (&str, &str) {
    let Some(open) = line.find('(') else {
        return ("", "");
    };
    let mut depth = 0usize;
    for (offset, c) in line[open..].char_indices() {
        match c {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let close = open + offset;
                    return (&line[open + 1..close], &line[close + 1..]);
                }
            }
            _ => {}
        }
    }
    (&line[open + 1..], "")
}

/// Whether `text` names the type at `path`, and not a longer one beginning
/// with it.
fn names(text: &str, path: &str) -> bool {
    text.match_indices(path).any(|(at, _)| {
        !text[at + path.len()..].starts_with(|c: char| c.is_alphanumeric() || c == '_')
    })
}

/// The traits whose implementation hands a caller a value of the type.
const BUILDS: &[&str] = &[
    "core::default::Default for ",
    "core::convert::From<",
    "core::convert::TryFrom<",
    "core::str::traits::FromStr for ",
    "serde_core::de::Deserialize<'de> for ",
    "core::iter::traits::collect::FromIterator<",
];

/// A `#[non_exhaustive]` struct cannot be written out as a literal outside the
/// crate, so a caller holds one only if the crate hands it one: through a
/// constructor, `Default` or a conversion, or as what a function returns or a
/// field holds. A public function taking one no caller can come by is a
/// promise nobody can use, and taking it back is still a breaking release.
#[test]
fn no_public_function_takes_a_struct_no_caller_can_come_by() {
    let listing = listing();
    let lines: Vec<&str> = listing.lines().collect();

    // Each sealed struct, under every path the listing names it by, with
    // whether its own lines give a caller a way to one.
    let mut sealed: Vec<(Vec<&str>, bool)> = Vec::new();
    for (at, line) in lines.iter().enumerate() {
        let Some(path) = line.strip_prefix("#[non_exhaustive] pub struct ") else {
            continue;
        };
        let path = path.split(['<', ' ', '(']).next().unwrap_or(path);
        let body = lines[at + 1..]
            .iter()
            .take_while(|line| !opens_an_item(line));
        let mut paths = vec![path];
        let mut built = false;
        for line in body {
            if let Some(implemented) = line.strip_prefix("impl") {
                // A re-export's lines name the type by its own path.
                if let Some((_, target)) = implemented.rsplit_once(" for ")
                    && !paths.contains(&target)
                {
                    paths.push(target);
                }
                built |= BUILDS.iter().any(|trait_| implemented.contains(trait_));
            } else if is_function(line) {
                built |= parameters_and_return(line).1.contains("Self");
            }
        }
        sealed.push((paths, built));
    }
    assert!(
        sealed.iter().any(|(paths, built)| {
            *built && paths.contains(&"zond_engine::model::target::Target")
        }),
        "the listing still spells a sealed struct and its constructor the way this \
         check reads them"
    );

    let handed_out = |paths: &[&str]| {
        lines.iter().any(|line| {
            if is_function(line) {
                return paths
                    .iter()
                    .any(|path| names(parameters_and_return(line).1, path));
            }
            // A public field of another type holding one.
            let Some((field, kind)) = line.strip_prefix("pub ").and_then(|l| l.split_once(": "))
            else {
                return false;
            };
            !opens_an_item(line)
                && !paths
                    .iter()
                    .any(|path| field.starts_with(&format!("{path}::")))
                && paths.iter().any(|path| names(kind, path))
        })
    };
    let unobtainable: Vec<Vec<&str>> = sealed
        .into_iter()
        .filter(|(paths, built)| !built && !handed_out(paths))
        .map(|(paths, _)| paths)
        .collect();

    let unusable: Vec<&str> = lines
        .iter()
        .filter(|line| is_function(line))
        .filter(|line| {
            let (parameters, _) = parameters_and_return(line);
            unobtainable
                .iter()
                .flatten()
                .any(|path| names(parameters, path))
        })
        .copied()
        .collect();
    assert!(
        unusable.is_empty(),
        "public functions taking a sealed struct no caller can come by: {unusable:#?}\n\n\
         Give the struct a constructor, or keep the function to the crate."
    );
}
