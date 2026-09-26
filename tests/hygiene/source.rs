// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading the engine's source as code
//!
//! Every census here looks for a name in the library's production code, and
//! every one of them is only as good as its idea of where that code is. Two
//! things stand between the text of a file and its code:
//!
//! - **What is not code at all.** A comment naming a call is prose, and a
//!   string holding one is data. Both also hold brackets, and a census that
//!   finds the end of a test module by counting braces reads `'{'` or `"]"`
//!   as one: the module then ends early, and its fixtures count as the engine,
//!   or never ends, and everything after it drops out of sight.
//! - **What is compiled only for a test.** A fixture seeding a store or opening
//!   a socket says nothing about how the engine does either, whether it sits in
//!   a `#[cfg(test)]` item inside a file or is a whole file some parent declares
//!   under one.
//!
//! So the censuses share one reading, here: [`sources`] names the files a
//! build without tests compiles, and [`production`] turns a file's text into
//! its code with comments and literals blanked and test items taken out.
//! Having one reading means a census cannot be the one that forgot a case.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Every Rust file under `src/`, in a stable order.
pub(crate) fn every_source() -> Vec<PathBuf> {
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
        let mut entries: Vec<_> = fs::read_dir(dir)
            .expect("src is readable")
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        entries.sort();
        for path in entries {
            if path.is_dir() {
                walk(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }
    let mut out = Vec::new();
    walk(Path::new("src"), &mut out);
    out
}

/// The files whose contents describe how the engine behaves, which is every
/// source that is not compiled only for a test.
pub(crate) fn sources() -> Vec<PathBuf> {
    let test_only = test_only_modules();
    every_source()
        .into_iter()
        .filter(|path| !test_only.iter().any(|module| path.starts_with(module)))
        .collect()
}

/// A path as the censuses write it, whichever platform read it.
pub(crate) fn display(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

/// The code of a file's text: [`code_of`], less what [`without_tests`] takes
/// out.
pub(crate) fn production(text: &str) -> String {
    without_tests(&code_of(text))
}

/// The files and directories belonging to a module some parent compiles only
/// for a test.
///
/// [`without_tests`] strips a `#[cfg(test)] mod tests { … }` written *inside*
/// a file. It cannot see `#[cfg(test)] pub(crate) mod fixture;` in the parent,
/// which makes a whole file test-only, and `src/export/fixture.rs` is exactly
/// that. A directory stands for every module under it, which the gate on their
/// ancestor compiles out as surely as it does the ancestor.
fn test_only_modules() -> BTreeSet<PathBuf> {
    let mut out = BTreeSet::new();
    for path in every_source() {
        let text = fs::read_to_string(&path).expect("a source file is readable");
        let code = code_of(&text);
        let lines: Vec<&str> = code.lines().collect();
        for pair in lines.windows(2) {
            let condition = pair[0]
                .trim()
                .strip_prefix("#[cfg(")
                .and_then(|rest| rest.strip_suffix(")]"));
            if !condition.is_some_and(implies_test) {
                continue;
            }
            let next = pair[1].trim().trim_end_matches(';');
            let Some(name) = next.split_whitespace().last() else {
                continue;
            };
            if !next.contains("mod ") || !next.ends_with(name) || next.contains('{') {
                continue;
            }

            // `src/export.rs` declaring `mod fixture;` means `src/export/fixture.rs`.
            let dir = match path.file_stem().and_then(|s| s.to_str()) {
                Some("lib") | Some("mod") => path.parent().expect("a parent").to_path_buf(),
                Some(stem) => path.parent().expect("a parent").join(stem),
                None => continue,
            };
            out.insert(dir.join(format!("{name}.rs")));
            out.insert(dir.join(name));
        }
    }
    out
}

/// Whether `c` can be part of an identifier.
pub(crate) fn is_ident(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// `text` with every comment and every string and character literal blanked,
/// so what is left is code a name can be looked for in and a bracket counted
/// in.
///
/// Blanked rather than removed: each character becomes a space and a newline
/// stays one, so nothing that was apart runs together and every line keeps its
/// number. A doc comment naming a call is not a call and a string mentioning
/// one is not either, and a brace inside `'{'` or `"{}"` is no longer there
/// for [`without_tests`] to miscount.
pub(crate) fn code_of(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let blank = |out: &mut String, from: &[char]| {
        out.extend(from.iter().map(|&c| if c == '\n' { '\n' } else { ' ' }));
    };

    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        let starts_word = i == 0 || !is_ident(chars[i - 1]);

        let end = if c == '/' && next == Some('/') {
            // A line comment, doc comments included.
            chars[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(chars.len(), |at| i + at)
        } else if c == '/' && next == Some('*') {
            // A block comment, which nests.
            let mut depth = 0usize;
            let mut j = i;
            while j < chars.len() {
                match (chars[j], chars.get(j + 1)) {
                    ('/', Some('*')) => {
                        depth += 1;
                        j += 2;
                    }
                    ('*', Some('/')) => {
                        depth -= 1;
                        j += 2;
                        if depth == 0 {
                            break;
                        }
                    }
                    _ => j += 1,
                }
            }
            j
        } else if starts_word && (c == 'r' || (matches!(c, 'b' | 'c') && next == Some('r'))) {
            // A raw string, if a quote follows the hashes. A raw identifier
            // like `r#type` has none and is left alone.
            let mut j = i + if c == 'r' { 1 } else { 2 };
            let hashes = chars[j..].iter().take_while(|&&c| c == '#').count();
            j += hashes;
            if chars.get(j) != Some(&'"') {
                out.push(c);
                i += 1;
                continue;
            }
            let closing: Vec<char> = std::iter::once('"')
                .chain(std::iter::repeat_n('#', hashes))
                .collect();
            (j + 1..=chars.len() - closing.len().min(chars.len()))
                .find(|&k| chars[k..].starts_with(&closing))
                .map_or(chars.len(), |k| k + closing.len())
        } else if c == '"' {
            // A string, stepping over each escape whole.
            let mut j = i + 1;
            while j < chars.len() && chars[j] != '"' {
                j += if chars[j] == '\\' { 2 } else { 1 };
            }
            (j + 1).min(chars.len())
        } else if c == '\'' && next == Some('\\') {
            // An escaped character literal, whatever it escapes.
            chars
                .get(i + 3..)
                .and_then(|rest| rest.iter().position(|&c| c == '\''))
                .map_or(chars.len(), |at| i + 3 + at + 1)
        } else if c == '\'' && chars.get(i + 2) == Some(&'\'') {
            // A character literal. A lifetime has no closing quote two along.
            i + 3
        } else {
            out.push(c);
            i += 1;
            continue;
        };

        blank(&mut out, &chars[i..end.min(chars.len())]);
        i = end.max(i + 1);
    }
    out
}

/// `code` with the items compiled only for a test removed, whatever spells
/// the condition: see [`implies_test`].
///
/// Bracket-counted rather than parsed, which is sound once [`code_of`] has
/// blanked every bracket a literal or a comment held. An item whose brackets
/// never close is kept whole: counted as production it can only add a
/// finding, where dropped it would take every line after it out of sight.
pub(crate) fn without_tests(code: &str) -> String {
    let mut kept = String::with_capacity(code.len());
    let mut rest = code;

    while let Some((at, attribute_end)) = next_test_only_attribute(rest) {
        kept.push_str(&rest[..at]);
        let item = &rest[attribute_end..];
        let Some(len) = item_len(item) else {
            rest = &rest[at..];
            break;
        };
        rest = &item[len..];
    }
    kept.push_str(rest);
    kept
}

/// Where the next `#[cfg(…)]` whose condition implies [`implies_test`] starts
/// in `code`, and where the attribute ends.
fn next_test_only_attribute(code: &str) -> Option<(usize, usize)> {
    let mut from = 0;
    while let Some(found) = code[from..].find("#[cfg(") {
        let at = from + found;
        let condition = at + "#[cfg(".len();
        let close = condition + closing_paren(&code[condition..])?;
        if code[close + 1..].starts_with(']') && implies_test(&code[condition..close]) {
            return Some((at, close + 2));
        }
        from = condition;
    }
    None
}

/// The offset of the `)` closing a parenthesis opened just before `code`.
fn closing_paren(code: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in code.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' if depth == 0 => return Some(offset),
            b')' => depth -= 1,
            _ => {}
        }
    }
    None
}

/// Whether a `cfg` condition holds only when compiling a test: `test` itself,
/// an `all` with such a term, or an `any` made only of them. `not(test)` names
/// the word and is the opposite, and `any(test, feature = "…")` also compiles
/// into a build that enables the feature, so neither counts.
fn implies_test(condition: &str) -> bool {
    let condition = condition.trim();
    if condition == "test" {
        return true;
    }
    let terms = |name: &str| {
        condition
            .strip_prefix(name)
            .and_then(|rest| rest.trim_start().strip_prefix('('))
            .and_then(|rest| rest.strip_suffix(')'))
            .map(top_level_terms)
    };
    if let Some(terms) = terms("all") {
        return terms.iter().any(|term| implies_test(term));
    }
    if let Some(terms) = terms("any") {
        return !terms.is_empty() && terms.iter().all(|term| implies_test(term));
    }
    false
}

/// The comma-separated terms of a condition list, split only at its own level.
fn top_level_terms(list: &str) -> Vec<&str> {
    let mut terms = Vec::new();
    let (mut depth, mut start) = (0usize, 0);
    for (offset, byte) in list.bytes().enumerate() {
        match byte {
            b'(' => depth += 1,
            b')' => depth = depth.saturating_sub(1),
            b',' if depth == 0 => {
                terms.push(&list[start..offset]);
                start = offset + 1;
            }
            _ => {}
        }
    }
    terms.push(&list[start..]);
    terms.retain(|term| !term.trim().is_empty());
    terms
}

/// How many bytes of `code` the item it starts with takes up, attributes
/// included: through the `}` closing its body, or through the `;` or `,`
/// ending an item that has none (`mod fixture;`, a field, a variant), or up
/// to the `}` closing whatever holds it. `None` for an item that runs off the
/// end of the file still open.
fn item_len(code: &str) -> Option<usize> {
    let mut depth = 0usize;
    for (offset, byte) in code.bytes().enumerate() {
        match byte {
            b'(' | b'[' | b'{' => depth += 1,
            b')' | b']' | b'}' if depth == 0 => return Some(offset),
            b'}' if depth == 1 => return Some(offset + 1),
            b')' | b']' | b'}' => depth -= 1,
            b';' | b',' if depth == 0 => return Some(offset + 1),
            _ => {}
        }
    }
    None
}

/// **Code compiled only under a test is left out, whatever spells the
/// condition, and nothing else is.**
///
/// A fixture behind `#[cfg(all(test, unix))]` is as much test code as one
/// behind `#[cfg(test)]`, and counting it would list a fixture as an ungated
/// writer. The other way round is worse: a condition that merely names
/// `test` without implying it, or an item without a body, must not take the
/// production code after it out of the census with it.
#[test]
fn only_code_compiled_solely_for_tests_is_left_out() {
    let text = "\
fn production_one() { store.insert(1); }
#[cfg(all(test, unix))]
mod unix_tests { fn seed() { store.insert(2); } }
#[cfg(any(test, feature = \"test-support\"))]
fn support() { store.entry(3); }
#[cfg(not(test))]
fn release_only() { store.get_mut(4); }
#[cfg(test)]
mod fixture;
fn production_two() { store.insert(5); }
#[cfg(any(test, all(test, windows)))]
fn helper() { store.insert(6); }
";
    let kept = production(text);
    for production in ["insert(1)", "entry(3)", "get_mut(4)", "insert(5)"] {
        assert!(
            kept.contains(production),
            "{production} was dropped:\n{kept}"
        );
    }
    for test_only in ["insert(2)", "insert(6)"] {
        assert!(!kept.contains(test_only), "{test_only} was kept:\n{kept}");
    }
}

/// **A bracket in a literal or a comment neither ends a test item nor keeps
/// it open.**
///
/// Each line of the fixture module holds one bracket the compiler does not
/// count, in every kind of literal and comment the language has, and a
/// lifetime, whose quote opens no literal. Counted as code, the openers keep
/// the module open to the end of the file and the call after it drops out of
/// the census; the closers end it early and its fixture reads as the engine.
#[test]
fn brackets_in_literals_and_comments_are_not_counted() {
    let text = r##"
#[cfg(test)]
mod tests {
    // an unclosed { in a line comment
    /* and ( in a block /* that nests [ */ */
    const OPEN: &str = "{[(\"{";
    const RAW: &str = r#"{ "( ["#;
    const BYTES: &[u8] = br"{";
    const BYTE: u8 = b'{';
    const CHAR: char = '(';
    const QUOTE: char = '\'';
    const UNICODE: char = '\u{7B}';
    fn borrow<'a>(text: &'a str) -> &'a str { text }
    fn seed() { store.insert(2); }
    const CLOSE: &str = "}";
    const CLOSING: char = '}';
}
fn late(discovery: Discovery) -> Discovery { discovery.with_source_ip(ip) }
"##;
    let kept = production(text);
    assert!(
        kept.contains(".with_source_ip("),
        "the late call was dropped:\n{kept}"
    );
    assert!(
        !kept.contains("store.insert"),
        "the fixture was kept:\n{kept}"
    );
}

/// **Code after the last test item of any file in the tree is still read.**
///
/// The census has to see a production line wherever a file puts it, and the
/// likeliest place for a new one to land unseen is after a test module,
/// whose fixtures hold more quoted brackets than any other code. So every
/// source is read as the census reads it with a call appended at its end, and
/// the call has to survive.
#[test]
fn a_call_after_every_test_item_in_the_tree_is_seen() {
    const APPENDED: &str = "fn appended_production() { marker_call_seen_by_the_census(); }";
    let dropped: Vec<String> = every_source()
        .iter()
        .filter(|path| {
            let text = fs::read_to_string(path).expect("a source file is readable");
            !production(&format!("{text}\n{APPENDED}\n")).contains(APPENDED)
        })
        .map(|path| display(path))
        .collect();
    assert!(
        dropped.is_empty(),
        "code appended to these files is not seen as production: {dropped:?}"
    );
}
