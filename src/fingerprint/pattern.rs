// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Pattern engine selection
//!
//! One [`CompiledPattern`] is a signature's compiled regex, built by whichever
//! engine can handle it. Two engines back it, tried in order:
//!
//! * **[`CompiledPattern::Fast`]**, the linear-time `regex` (RE2) engine. The
//!   primary: it does not backtrack, so its match time is linear in the input
//!   no matter the pattern. Every pattern it accepts runs here.
//! * **[`CompiledPattern::Fancy`]**, the `fancy-regex` backtracking engine,
//!   reached *only* when the fast engine rejects a pattern (backreferences,
//!   lookaround). Backtracking can be superlinear, so it is bounded by a
//!   backtrack-step limit ([`BACKTRACK_LIMIT`]): a match that would exceed it is
//!   reported as "no match" rather than allowed to run away.
//!
//! Trying the fast engine first keeps the overwhelming majority of signatures on
//! the linear path and confines the backtracking engine, and its
//! runtime-failure semantics, to the few patterns that genuinely need it.
//!
//! ## Why a step limit, not a wall clock
//!
//! The bound is a count of backtracking steps, not elapsed time. A synchronous
//! regex match cannot be interrupted mid-flight, so a wall-clock "timeout" would
//! either need a watchdog thread that leaves the runaway match burning a core
//! until it finishes anyway, or would fire non-deterministically depending on
//! machine load. A step ceiling instead bounds the *work itself*, and does so
//! deterministically: the same pattern and input always resolve the same way on
//! every machine, which is what keeps the signature corpus tests reproducible.
//! The engine already runs off the reactor (analysis is on the blocking pool),
//! so a bounded-but-nontrivial match can never stall the scheduler.
//!
//! ## Classes mean ASCII
//!
//! `\d`, `\w` and `\s`, their negations and the word boundaries `\b` and
//! `\B` are compiled as their ASCII readings, `[0-9]`, `[0-9A-Za-z_]` and
//! `[\t\n\v\f\r ]`, whichever engine takes the pattern; see
//! [`ascii_classes`]. That is what they mean in the Ruby dialect the imported
//! corpus was written in, so a rule matches what its author tested it
//! against, and in the Unicode readings both engines default to they are what
//! a compiled corpus is mostly made of. `\w` alone is some seven hundred
//! ranges, which a bounded repetition copies once per count: a rule opening
//! on `[\w.-]{1,512}` compiled to 28 MB and its search cache to 18 more, and
//! the corpus as a whole to 600 MB and 200 MB of caches, against 260 and 90
//! read as ASCII. A Unicode word boundary also keeps the lazy DFA off any text
//! holding a byte past ASCII, which is every page in a language other than
//! English, where an ASCII one does not.
//!
//! A rule that means a Unicode class says so with `\p{…}`, which is left as
//! written.
//!
//! ## Shared with the build
//!
//! This module is free of any crate-internal dependency (logging,
//! models, ...) so `build.rs` can `include!` it and validate authored patterns
//! with the *exact* engine-selection logic the runtime uses. The build and the
//! runtime therefore cannot disagree on which patterns are accepted: a signature
//! that compiles at build time is one the runtime can compile, and a signature
//! the build rejects never ships.

use fancy_regex::RegexBuilder as FancyRegexBuilder;
use regex::{Regex, RegexBuilder};

/// Backtracking-step ceiling for the fancy engine. A match that exceeds it is
/// reported as no match, so a pathological backref/lookaround pattern on an
/// adversarial input is bounded instead of running away.
///
/// This mirrors `fancy-regex`'s own default; we set it explicitly because it is
/// the load-bearing safety bound of the whole backtracking path, not an
/// incidental default worth leaving implicit.
const BACKTRACK_LIMIT: usize = 1_000_000;

/// A signature's regex, compiled by whichever engine could express it. See the
/// module docs for how the engine is chosen and bounded.
#[derive(Debug)]
pub enum CompiledPattern {
    /// The linear-time `regex` engine, used for every pattern it accepts.
    Fast(Regex),
    /// The bounded `fancy-regex` backtracking engine, used only for patterns
    /// the fast engine rejects (backreferences, lookaround).
    Fancy(fancy_regex::Regex),
}

/// Both engines rejected a pattern. Carries each engine's error so the build can
/// report precisely why a pattern is unusable.
#[derive(Debug)]
pub struct PatternError {
    /// Why the linear engine rejected it.
    pub fast: regex::Error,
    /// Why the backtracking engine rejected it.
    pub fancy: fancy_regex::Error,
}

impl std::fmt::Display for PatternError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "rejected by the linear engine ({}) and the backtracking engine ({})",
            self.fast, self.fancy
        )
    }
}

/// A signature's successful match: the text of its version capture group, if the
/// signature asked for one and it was present.
///
/// `allow(dead_code)`: read by the runtime matcher rather than `build.rs`. This
/// module is shared by both, and each uses a different subset.
#[allow(dead_code)]
pub struct PatternMatch {
    /// The captured version string. `None` means the pattern matched but named
    /// no version group, or the group did not participate in the match.
    pub version: Option<String>,

    /// How many characters of the response the whole match spanned. Longer means
    /// the signature pinned down more of the bytes, so a specific pattern outranks
    /// a generic one that matched the same response.
    pub match_len: usize,

    /// Every capture group, index 0 being the whole match, when the caller asked
    /// for them via
    /// [`identify_with_captures`](CompiledPattern::identify_with_captures).
    ///
    /// `None` means they were not requested, never that the pattern had none.
    /// Collecting them allocates, and the rules that need them are a minority of
    /// a corpus matched thousands of times per banner.
    pub captures: Option<Vec<String>>,
}

/// Compiles `pattern`, trying the linear engine first and the bounded
/// backtracking engine only if the linear one cannot express the pattern.
///
/// `size_limit` caps the compiled program's memory footprint on both engines,
/// so the same oversized pattern is rejected identically whichever path it takes.
/// Returns [`PatternError`] only when *neither* engine accepts the pattern.
pub fn compile(pattern: &str, size_limit: usize) -> Result<CompiledPattern, PatternError> {
    // Primary: the linear-time engine. Anything it accepts matches without
    // backtracking, so it needs no runtime bound.
    let fast = match RegexBuilder::new(&ascii_classes(pattern, Boundaries::Flagged))
        .size_limit(size_limit)
        .build()
    {
        Ok(regex) => return Ok(CompiledPattern::Fast(regex)),
        Err(err) => err,
    };

    // Fallback: only patterns the fast engine cannot express (backrefs,
    // lookaround). Bound its backtracking, and cap the size of the inner program
    // it delegates to `regex` at the same limit the fast path used.
    match FancyRegexBuilder::new(&ascii_classes(pattern, Boundaries::LookedAround))
        .backtrack_limit(BACKTRACK_LIMIT)
        .delegate_size_limit(size_limit)
        .build()
    {
        Ok(regex) => Ok(CompiledPattern::Fancy(regex)),
        Err(fancy) => Err(PatternError { fast, fancy }),
    }
}

/// How [`ascii_classes`] spells an ASCII word boundary, which no one spelling
/// gives both engines.
#[derive(Debug, Clone, Copy)]
enum Boundaries {
    /// `(?-u:\b)`, which the linear engine runs in its DFA and the
    /// backtracking engine refuses.
    Flagged,
    /// As look-arounds on either side, which the backtracking engine runs and
    /// the linear engine refuses.
    LookedAround,
}

/// `pattern` with each Perl class and word boundary spelled as its ASCII
/// reading. See the module docs for why.
///
/// Written out in the pattern rather than asked of the engines, because
/// neither can be asked for it alone: turning Unicode off turns it off for `.`
/// and for negated classes too, which then match a lone byte of a multi-byte
/// character, and a pattern over text may not. A class is spelled as a POSIX
/// class, which both engines read as ASCII, and a boundary as `boundaries`
/// says.
///
/// A lexical pass that knows only what it must: an escape is a backslash and
/// the character after it, so `\\d` stays a backslash and a `d`; a bracketed
/// class may nest, may open on a `]` it holds literally, and may hold a POSIX
/// class, inside which nothing is rewritten. A boundary inside a class is left
/// alone, since the engines refuse it there anyway.
fn ascii_classes(pattern: &str, boundaries: Boundaries) -> String {
    let mut out = String::with_capacity(pattern.len());
    let mut chars = pattern.char_indices().peekable();
    // How many bracketed classes the cursor is inside.
    let mut depth = 0usize;

    while let Some((at, c)) = chars.next() {
        match c {
            '\\' => {
                let Some((_, escaped)) = chars.next() else {
                    out.push(c);
                    break;
                };
                let class = match escaped.to_ascii_lowercase() {
                    'd' => Some("digit"),
                    'w' => Some("word"),
                    's' => Some("space"),
                    _ => None,
                };
                match class {
                    Some(name) => {
                        let negated = if escaped.is_ascii_uppercase() {
                            "^"
                        } else {
                            ""
                        };
                        if depth == 0 {
                            out.push_str(&format!("[[:{negated}{name}:]]"));
                        } else {
                            out.push_str(&format!("[:{negated}{name}:]"));
                        }
                    }
                    None if depth == 0 && matches!(escaped, 'b' | 'B') => {
                        out.push_str(match (boundaries, escaped) {
                            (Boundaries::Flagged, 'b') => r"(?-u:\b)",
                            (Boundaries::Flagged, _) => r"(?-u:\B)",
                            (Boundaries::LookedAround, 'b') => {
                                r"(?:(?<=[[:word:]])(?![[:word:]])|(?<![[:word:]])(?=[[:word:]]))"
                            }
                            (Boundaries::LookedAround, _) => {
                                r"(?:(?<=[[:word:]])(?=[[:word:]])|(?<![[:word:]])(?![[:word:]]))"
                            }
                        });
                    }
                    None => {
                        out.push(c);
                        out.push(escaped);
                    }
                }
            }
            '[' if depth > 0 && pattern[at..].starts_with("[:") => {
                // A POSIX class, copied whole. One that never closes is left
                // for the engine to refuse.
                match pattern[at..].find(":]") {
                    Some(end) => {
                        out.push_str(&pattern[at..at + end + 2]);
                        while chars.peek().is_some_and(|&(next, _)| next < at + end + 2) {
                            chars.next();
                        }
                    }
                    None => out.push(c),
                }
            }
            '[' => {
                depth += 1;
                out.push(c);
                // A negation, then a `]` first in the class, are literal.
                if let Some(&(_, '^')) = chars.peek() {
                    out.push('^');
                    chars.next();
                }
                if let Some(&(_, ']')) = chars.peek() {
                    out.push(']');
                    chars.next();
                }
            }
            ']' if depth > 0 => {
                depth -= 1;
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    out
}

impl CompiledPattern {
    /// The number of capture groups, counting group 0 (the whole match). Used to
    /// validate a signature's `version_group` at build time against both engines
    /// uniformly.
    ///
    /// `allow(dead_code)`: consumed by `build.rs` validation rather than the
    /// runtime matcher. This module is shared by both, and each uses a different
    /// subset.
    #[allow(dead_code)]
    pub fn captures_len(&self) -> usize {
        match self {
            CompiledPattern::Fast(regex) => regex.captures_len(),
            CompiledPattern::Fancy(regex) => regex.captures_len(),
        }
    }

    /// The declared names of this pattern's named capture groups, unnamed groups
    /// skipped. Lets a build check that a `(?<name>…)` a `bind` expects actually
    /// exists in the pattern, without text to match it against.
    ///
    /// `allow(dead_code)`: consumed by `build.rs` validation rather than the
    /// runtime matcher. This module is shared by both, and each uses a different
    /// subset.
    #[allow(dead_code)]
    pub fn capture_names(&self) -> Vec<String> {
        match self {
            CompiledPattern::Fast(regex) => {
                regex.capture_names().flatten().map(String::from).collect()
            }
            CompiledPattern::Fancy(regex) => {
                regex.capture_names().flatten().map(String::from).collect()
            }
        }
    }

    /// The value of the named capture group `name`, if the pattern matches `text`
    /// and the group participated. How a Tier-1 `bind` pulls a value out of a
    /// match by name rather than by numeric index.
    ///
    /// `allow(dead_code)`: consumed by the flow interpreter, not `build.rs`.
    #[allow(dead_code)]
    pub fn capture(&self, text: &str, name: &str) -> Option<String> {
        match self {
            CompiledPattern::Fast(regex) => regex
                .captures(text)
                .and_then(|captures| captures.name(name))
                .map(|group| group.as_str().to_string()),
            CompiledPattern::Fancy(regex) => regex
                .captures(text)
                .ok()
                .flatten()
                .and_then(|captures| captures.name(name))
                .map(|group| group.as_str().to_string()),
        }
    }

    /// Matches `text`, returning [`PatternMatch`] on a match (with the
    /// `version_group` capture if requested) or `None` if the pattern does not
    /// match.
    ///
    /// A fancy-engine runtime failure, meaning the backtrack limit or the
    /// recursion stack being exceeded, is reported as no match: the outcome is
    /// bounded and safe rather than a hang. The linear engine has no such failure
    /// mode.
    ///
    /// `allow(dead_code)`: consumed by the runtime matcher, not `build.rs`. This
    /// module is shared by both, and each uses a different subset.
    #[allow(dead_code)]
    pub fn identify(&self, text: &str, version_group: Option<u8>) -> Option<PatternMatch> {
        self.identify_with_captures(text, version_group, false)
    }

    /// [`identify`](Self::identify), optionally keeping every capture group.
    ///
    /// The groups are wanted only by the rules that carry `{capture:N}` templates
    /// in their metadata, which is a minority of a large corpus, so collecting
    /// them is asked for rather than always done. On the hot path of a scan that
    /// matches thousands of signatures against a banner, the allocation per match
    /// is the whole cost of this function.
    ///
    /// Index 0 is the whole match, matching the numbering a pattern's own groups
    /// use and the numbering `version_group` is written against. An unmatched
    /// optional group yields an empty string rather than being skipped, so a
    /// template naming it resolves to nothing instead of to the next group along.
    pub fn identify_with_captures(
        &self,
        text: &str,
        version_group: Option<u8>,
        keep_captures: bool,
    ) -> Option<PatternMatch> {
        macro_rules! extract {
            ($captures:expr) => {{
                let captures = $captures;
                // Group 0 is the whole match; its length is how much of the
                // response the pattern pinned down, which ranks a specific
                // signature over a generic one that matched the same bytes.
                let match_len = captures.get(0).map_or(0, |m| m.as_str().chars().count());
                let version = version_group
                    .and_then(|group| captures.get(group as usize))
                    .map(|m| m.as_str().to_string());
                let groups = keep_captures.then(|| {
                    (0..captures.len())
                        .map(|index| {
                            captures
                                .get(index)
                                .map(|m| m.as_str().to_string())
                                .unwrap_or_default()
                        })
                        .collect::<Vec<String>>()
                });
                (version, groups, match_len)
            }};
        }

        let (version, captures, match_len) = match self {
            CompiledPattern::Fast(regex) => extract!(regex.captures(text)?),
            // `Err` is a bounded runtime failure (backtrack limit / stack
            // overflow); `Ok(None)` is a clean non-match. Both mean "no match"
            // here.
            CompiledPattern::Fancy(regex) => extract!(regex.captures(text).ok()??),
        };
        Some(PatternMatch {
            version,
            captures,
            match_len,
        })
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

    const LIMIT: usize = 32 * 1024 * 1024;

    #[test]
    fn plain_pattern_takes_the_linear_engine() {
        let compiled = compile(r"^SSH-2\.0-OpenSSH_([\w.]+)", LIMIT).expect("compiles");
        assert!(matches!(compiled, CompiledPattern::Fast(_)));

        let m = compiled
            .identify("SSH-2.0-OpenSSH_9.6p1", Some(1))
            .expect("matches");
        assert_eq!(m.version.as_deref(), Some("9.6p1"));
        assert!(compiled.identify("HTTP/1.1 200 OK", Some(1)).is_none());
    }

    #[test]
    fn backreference_pattern_falls_back_to_the_fancy_engine() {
        // A backreference is unsupported by the linear engine, so this exercises
        // the fallback path, which build.rs accepts rather than rejecting the
        // pattern outright.
        let compiled = compile(r"^(\w+)\s+\1$", LIMIT).expect("compiles via fancy");
        assert!(matches!(compiled, CompiledPattern::Fancy(_)));

        assert!(compiled.identify("abc abc", None).is_some());
        assert!(compiled.identify("abc def", None).is_none());
    }

    #[test]
    fn lookahead_pattern_falls_back_to_the_fancy_engine() {
        let compiled = compile(r"foo(?=bar)", LIMIT).expect("compiles via fancy");
        assert!(matches!(compiled, CompiledPattern::Fancy(_)));

        assert!(compiled.identify("foobar", None).is_some());
        assert!(compiled.identify("foobaz", None).is_none());
    }

    #[test]
    fn fancy_pattern_can_still_capture_a_version_group() {
        // Fallback patterns must remain first-class: capture groups work the same.
        let compiled = compile(r"^(\w+)-\1/([\d.]+)$", LIMIT).expect("compiles via fancy");
        let m = compiled
            .identify("srv-srv/1.2.3", Some(2))
            .expect("matches");
        assert_eq!(m.version.as_deref(), Some("1.2.3"));
    }

    #[test]
    fn catastrophic_backtracking_is_bounded_not_a_hang() {
        // A backref forces the fancy engine; the nested quantifier makes the
        // match backtrack. With no terminating 'c' the engine would explore
        // exponentially, and the step limit turns that into a prompt no-match.
        let compiled = compile(r"(a+)+\1c", LIMIT).expect("compiles via fancy");
        assert!(matches!(compiled, CompiledPattern::Fancy(_)));
        let adversarial = "a".repeat(40);
        assert!(compiled.identify(&adversarial, None).is_none());
    }

    #[test]
    fn a_pattern_no_engine_can_compile_is_an_error() {
        // An unclosed group is a genuine syntax error in both engines.
        let err = compile("(", LIMIT).expect_err("neither engine compiles it");
        // Both arms are reported, so the build can explain the rejection fully.
        let msg = err.to_string();
        assert!(msg.contains("linear engine") && msg.contains("backtracking engine"));
    }

    #[test]
    fn captures_len_counts_the_whole_match_group() {
        assert_eq!(compile(r"^ab$", LIMIT).unwrap().captures_len(), 1); // group 0 only
        assert_eq!(compile(r"^(a)(b)$", LIMIT).unwrap().captures_len(), 3); // + two groups
        assert_eq!(compile(r"^(\w+)\s+\1$", LIMIT).unwrap().captures_len(), 2); // fancy: + one
    }

    #[test]
    fn capture_names_lists_the_named_groups_only() {
        // A named group is reported; an unnamed one is not.
        assert_eq!(
            compile(r"v(?<version>[0-9.]+) \((\w+)\)", LIMIT)
                .unwrap()
                .capture_names(),
            vec!["version".to_string()]
        );
        // A pattern with no named group reports none.
        assert!(
            compile(r"^\+PONG", LIMIT)
                .unwrap()
                .capture_names()
                .is_empty()
        );
        // The fancy engine (backreference) reports its named group too.
        assert_eq!(
            compile(r"(?<w>\w+)\s+\k<w>", LIMIT)
                .unwrap()
                .capture_names(),
            vec!["w".to_string()]
        );
    }

    /// **The Perl classes and word boundaries read as ASCII, on both engines.**
    ///
    /// The reading the corpus was written in, and the one a bounded
    /// repetition of a class can afford: see the module docs.
    #[test]
    fn perl_classes_and_word_boundaries_read_as_ascii_on_both_engines() {
        for (pattern, fancy) in [(r"^\w+\s\d+\b", false), (r"^(\w+)\s\d+\b(?!\1)", true)] {
            let compiled = compile(pattern, LIMIT).expect("compiles");
            assert_eq!(matches!(compiled, CompiledPattern::Fancy(_)), fancy);

            assert!(compiled.identify("abc_1 42", None).is_some(), "{pattern}");
            // A letter, a digit and a space from past ASCII.
            for text in ["caf\u{e9} 42", "abc \u{663}", "abc\u{a0}42"] {
                assert!(
                    compiled.identify(text, None).is_none(),
                    "{pattern} on {text:?}"
                );
            }
        }

        // A boundary between an ASCII word and a letter past it is one.
        let bounded = compile(r"\bfoo\b", LIMIT).expect("compiles");
        assert!(bounded.identify("\u{e9}foo\u{e9}", None).is_some());
        assert!(bounded.identify("afoo", None).is_none());
    }

    /// Only a class escape is rewritten: an escaped backslash, a POSIX class, a
    /// class opening on a literal `]`, a negated class and a Unicode property
    /// all mean what they meant.
    #[test]
    fn the_rewrite_leaves_everything_else_as_written() {
        let cases: &[(&str, &str, bool)] = &[
            (r"^\\d$", r"\d", true),
            (r"^\\d$", "1", false),
            (r"^[\d.]+$", "1.2.3", true),
            (r"^[^\s]+$", "a\u{a0}b", true),
            (r"^[\S]+$", "a b", false),
            (r"^[]\w]+$", "]a]", true),
            (r"^[^]\d]+$", "ab", true),
            (r"^[^]\d]+$", "a]", false),
            (r"^[[:alpha:]\d]+$", "a1", true),
            (r"^[a-z&&[^\d]]+$", "ab", true),
            (r"^\p{L}+$", "caf\u{e9}", true),
            (r"^\x41\u{42}$", "AB", true),
        ];
        for &(pattern, text, matches) in cases {
            let compiled = compile(pattern, LIMIT).expect(pattern);
            assert_eq!(
                compiled.identify(text, None).is_some(),
                matches,
                "{pattern} on {text:?}"
            );
        }
    }

    /// A bounded repetition of a class costs its count in ASCII ranges rather
    /// than in Unicode ones. Read as Unicode, this rule from the corpus
    /// compiles to 28 MB and is refused under a limit of one.
    #[test]
    fn a_long_repetition_of_a_class_compiles_small() {
        let pattern = r"^([\w.-]{1,512}) X2 WS_FTP Server ([\d.]{3,6}\s?\(\d+\))$";
        compile(pattern, 1024 * 1024).expect("compiles under a megabyte");
    }
}
