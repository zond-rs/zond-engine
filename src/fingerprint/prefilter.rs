// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Global-match prefilter
//!
//! Selecting matching signatures on a non-standard port means matching against
//! the *whole* set. Running every regex would be O(number of signatures) per
//! response, which is fine at a few thousand and not as the set grows. A
//! [`Prefilter`] narrows the field to a small candidate set first, so global
//! matching stays sublinear in the size of the database.
//!
//! ## The literal engine
//!
//! [`LiteralPrefilter`] extracts, for each signature, a set of literals such
//! that **any match must contain at least one of them**, and indexes them in an
//! Aho-Corasick automaton. A response's candidates are the signatures whose
//! literal appears in it, plus a small "always-run" bucket of signatures no
//! usable literal could be extracted from (pure-structural patterns, and those
//! written with look-arounds, which the extractor's parser does not read).
//!
//! ### Soundness
//!
//! Only required literals are used, extracted from a pattern's prefix (handling
//! alternations), the guaranteed inner runs of its mandatory parts (handling
//! alternations too), or its suffix. Each is a substring every match must
//! contain, so a signature is never wrongly excluded. This is checked against
//! the recorded-example corpus (`corpus.rs`): every example that matches its
//! pattern must select that pattern as a candidate.
//!
//! ### Case-insensitive patterns
//!
//! A pattern under `(?i)` reaches the extractor with every letter a class of
//! its cases, `[Ll][Ii][Nn][Uu][Xx]`, and a class is no literal. So before
//! extraction each class that holds exactly one ASCII letter's two cases is
//! read as that letter in lower case, and the automaton, which ignores ASCII
//! case, finds it in either. Every match holds one of the class's two
//! members there, so the literal is still one every match contains. `k` and
//! `s` are not folded: Unicode case folding adds the Kelvin sign and the long
//! s to their classes, which a match may hold and an ASCII-insensitive
//! literal would miss, so each ends the run it falls in.
//!
//! ### Cost per response
//!
//! Selection runs once per response, and a scan fingerprints every open port on
//! every host, so this is a hot path. A signature contributes several literals
//! and a response can hit any of them repeatedly, so hits are deduplicated as
//! they arrive, through a bitset indexed by *signature*. Both halves of that
//! are load-bearing. Indexing the bitset by literal instead makes it eight
//! times wider to allocate and zero without filtering anything more, and
//! dropping it to let the closing sort absorb the duplicates is slower still:
//! a response at the 4 KiB read cap can carry over a hundred thousand literal
//! hits, and the sort would see every one.
//!
//! [`Prefilter`] is a trait so a faster backend (e.g. `hyperscan`/`vectorscan`)
//! can replace the engine without touching callers.

use aho_corasick::AhoCorasick;
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Capture, Class, Hir, HirKind, Repetition};
use regex_syntax::parse;

use super::matcher::Signature;

/// Shortest literal worth indexing; below this, a literal is too common to
/// narrow anything and the signature is better left always-run.
const MIN_LITERAL_LEN: usize = 3;

/// The most literals an alternation contributes to a signature's set, past
/// which it guarantees nothing worth indexing. The corpus's widest guarded
/// alternation, a list of RPC program names, is a dozen.
const MAX_ALTERNATION_LITERALS: usize = 32;

/// Narrows the whole signature set to a candidate list for a response.
pub trait Prefilter: Send + Sync {
    /// Indices (into the signature set the prefilter was built from) that could
    /// possibly match `response`. Never omits a signature that would match.
    fn candidates(&self, response: &str) -> Vec<usize>;
}

/// A required-literal Aho-Corasick prefilter. See the module docs.
#[derive(Debug)]
pub struct LiteralPrefilter {
    automaton: AhoCorasick,
    /// Aho-Corasick pattern id -> the signature index that contributed it.
    literal_owner: Vec<usize>,
    /// Signatures with no usable required literal; always candidates.
    always_run: Vec<usize>,
    /// How many signatures were indexed, which is the width of the dedup
    /// bitset [`LiteralPrefilter::candidates`] allocates.
    signature_count: usize,
}

impl LiteralPrefilter {
    /// Builds the prefilter over `signatures`, indexing them by position.
    pub fn build(signatures: &[Signature]) -> Self {
        let mut literals: Vec<Vec<u8>> = Vec::new();
        let mut literal_owner: Vec<usize> = Vec::new();
        let mut always_run: Vec<usize> = Vec::new();

        for (idx, signature) in signatures.iter().enumerate() {
            match required_literals(signature.pattern()) {
                Some(lits) => {
                    for lit in lits {
                        literals.push(lit);
                        literal_owner.push(idx);
                    }
                }
                None => always_run.push(idx),
            }
        }

        // Ascii-case-insensitive so a literal indexed in one case still matches
        // a response in another; correctness (never dropping a match) is the
        // point, and the candidate's own regex makes the final decision.
        let automaton = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&literals)
            .expect("aho-corasick construction over signature literals");

        Self {
            automaton,
            literal_owner,
            always_run,
            signature_count: signatures.len(),
        }
    }
}

impl LiteralPrefilter {
    /// The signatures no literal narrows, which are candidates for every
    /// response.
    #[cfg(test)]
    pub(crate) fn always_run(&self) -> &[usize] {
        &self.always_run
    }
}

impl Prefilter for LiteralPrefilter {
    fn candidates(&self, response: &str) -> Vec<usize> {
        let mut selected = vec![0u64; self.signature_count.div_ceil(64).max(1)];
        let mut candidates = self.always_run.clone();
        for &owner in &self.always_run {
            selected[owner / 64] |= 1u64 << (owner % 64);
        }

        for m in self.automaton.find_overlapping_iter(response) {
            let owner = self.literal_owner[m.pattern().as_usize()];
            let (word, bit) = (owner / 64, 1u64 << (owner % 64));
            if selected[word] & bit == 0 {
                selected[word] |= bit;
                candidates.push(owner);
            }
        }

        candidates.sort_unstable();
        candidates
    }
}

/// A set of literals such that every match of `pattern` contains at least one,
/// or `None` if no such bounded set could be extracted (the caller then treats
/// the signature as always-run).
///
/// Tries, in order: the prefix literal set (which captures leading
/// alternations), the longest guaranteed inner literal, then the suffix set.
///
/// Extracted from the pattern with its case classes read as literals; see
/// [`folded`] and the module docs.
fn required_literals(pattern: &str) -> Option<Vec<Vec<u8>>> {
    let hir = folded(&parse(pattern).ok()?);

    if let Some(set) = literal_set(&hir, ExtractKind::Prefix) {
        return Some(set);
    }
    if let Some(inner) = required_set(&hir) {
        return Some(inner);
    }
    literal_set(&hir, ExtractKind::Suffix)
}

/// `hir` with each class holding exactly one ASCII letter's two cases read as
/// that letter in lower case, which every match of `hir` holds in one case or
/// the other, and the automaton finds in either.
fn folded(hir: &Hir) -> Hir {
    match hir.kind() {
        HirKind::Class(class) => match case_pair(class) {
            Some(lower) => Hir::literal([lower]),
            None => hir.clone(),
        },
        HirKind::Repetition(rep) => Hir::repetition(Repetition {
            sub: Box::new(folded(&rep.sub)),
            ..rep.clone()
        }),
        HirKind::Capture(capture) => Hir::capture(Capture {
            sub: Box::new(folded(&capture.sub)),
            ..capture.clone()
        }),
        HirKind::Concat(parts) => Hir::concat(parts.iter().map(folded).collect()),
        HirKind::Alternation(branches) => Hir::alternation(branches.iter().map(folded).collect()),
        _ => hir.clone(),
    }
}

/// The lower-case letter `class` holds both cases of and nothing else.
fn case_pair(class: &Class) -> Option<u8> {
    let members: Vec<u32> = match class {
        Class::Unicode(class) => class
            .ranges()
            .iter()
            .flat_map(|range| u32::from(range.start())..=u32::from(range.end()))
            .take(3)
            .collect(),
        Class::Bytes(class) => class
            .ranges()
            .iter()
            .flat_map(|range| u32::from(range.start())..=u32::from(range.end()))
            .take(3)
            .collect(),
    };
    let [upper, lower] = members[..] else {
        return None;
    };
    let lower = u8::try_from(lower).ok()?;
    (lower.is_ascii_lowercase() && u32::from(lower.to_ascii_uppercase()) == upper).then_some(lower)
}

/// The prefix or suffix literal set, if bounded and free of empty literals.
fn literal_set(hir: &Hir, kind: ExtractKind) -> Option<Vec<Vec<u8>>> {
    let mut extractor = Extractor::new();
    extractor.kind(kind);
    let seq = extractor.extract(hir);

    let literals = seq.literals()?; // `None` => unbounded => not usable
    if literals.is_empty() {
        return None;
    }

    let mut out = Vec::with_capacity(literals.len());
    for literal in literals {
        if literal.as_bytes().is_empty() {
            // An empty literal matches anywhere, so it cannot narrow the field.
            return None;
        }
        out.push(literal.as_bytes().to_vec());
    }
    Some(out)
}

/// A set of literals, each at least [`MIN_LITERAL_LEN`] long, one of which
/// appears in every match, found by walking the mandatory positions of the
/// HIR. `None` where none is guaranteed: a class, an optional repetition, or
/// an alternation with a branch that guarantees none.
///
/// Of a concatenation's parts, the one whose shortest literal is longest is
/// taken, and of those the one with fewest literals: a longer literal is
/// rarer in a response, and every literal is one more way to be selected. An
/// alternation guarantees one of its branches' literals, so its set is theirs
/// together, up to [`MAX_ALTERNATION_LITERALS`].
fn required_set(hir: &Hir) -> Option<Vec<Vec<u8>>> {
    match hir.kind() {
        HirKind::Literal(literal) => {
            (literal.0.len() >= MIN_LITERAL_LEN).then(|| vec![literal.0.to_vec()])
        }
        HirKind::Capture(capture) => required_set(&capture.sub),
        HirKind::Repetition(rep) if rep.min >= 1 => required_set(&rep.sub),
        HirKind::Concat(parts) => parts.iter().filter_map(required_set).max_by(|a, b| {
            let shortest = |set: &Vec<Vec<u8>>| set.iter().map(Vec::len).min();
            shortest(a)
                .cmp(&shortest(b))
                .then_with(|| b.len().cmp(&a.len()))
        }),
        HirKind::Alternation(branches) => {
            let mut set = Vec::new();
            for branch in branches {
                set.extend(required_set(branch)?);
            }
            (set.len() <= MAX_ALTERNATION_LITERALS).then_some(set)
        }
        _ => None,
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
    use crate::fingerprint::signature::MatchRule;
    use proptest::prelude::*;

    fn sig(pattern: &str) -> Signature {
        Signature::new(
            "svc",
            &MatchRule {
                name: None,
                pattern: pattern.to_string(),
                version_group: None,
                vendor: None,
                product: None,
                context: None,
                example: None,
                metadata: None,
            },
        )
    }

    #[test]
    fn selects_by_prefix_literal_and_skips_non_candidates() {
        let sigs = [sig(r"^SSH-[\d.]+-OpenSSH"), sig(r"^HTTP/1\.[01]")];
        let pf = LiteralPrefilter::build(&sigs);

        let ssh = pf.candidates("SSH-2.0-OpenSSH_9.6");
        assert!(ssh.contains(&0));
        assert!(!ssh.contains(&1)); // the HTTP signature is filtered out
    }

    #[test]
    fn selects_by_inner_literal() {
        // No prefix literal (leading capture/class), but a strong inner literal.
        let sigs = [sig(r"^(\S{1,64}) FTP Server \(Version ([\d.]+)\)")];
        let pf = LiteralPrefilter::build(&sigs);
        assert!(
            pf.candidates("host.example FTP Server (Version 1.2.3)")
                .contains(&0)
        );
        assert!(pf.candidates("SSH-2.0-OpenSSH_9.6").is_empty());
    }

    #[test]
    fn unfilterable_pattern_is_always_a_candidate() {
        // A pure-structural pattern yields no usable literal: always-run.
        let sigs = [sig(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")];
        let pf = LiteralPrefilter::build(&sigs);
        assert!(pf.candidates("anything at all").contains(&0));
    }

    /// The claim the dedup bitset makes: a signature is listed once, however
    /// many of its literals the response carries and however often.
    #[test]
    fn a_signature_is_listed_once_however_many_of_its_literals_hit() {
        let sigs = [
            sig(r"^(?:Postfix|Sendmail|Exim) SMTP"),
            sig(r"^HTTP/1\.[01]"),
        ];
        let pf = LiteralPrefilter::build(&sigs);

        let response = "Postfix SMTP / Sendmail SMTP / Exim SMTP / Postfix SMTP";
        let owned = pf.literal_owner.iter().filter(|&&o| o == 0).count();
        assert!(owned > 1, "the alternation gives it several literals");
        assert_eq!(pf.candidates(response), vec![0]);
    }

    #[test]
    fn case_insensitive_literal_still_selects() {
        let sigs = [sig(r"^Server: nginx")];
        let pf = LiteralPrefilter::build(&sigs);
        assert!(pf.candidates("server: NGINX/1.25").contains(&0));
    }

    /// A case-insensitive pattern is narrowed by its letters like any other,
    /// in whichever case a response writes them, rather than matched against
    /// every response.
    #[test]
    fn a_case_insensitive_pattern_is_narrowed_by_its_letters() {
        let sigs = [sig(r"(?i)^(.{0,64}) Linux ([\w.-]*)$")];
        let pf = LiteralPrefilter::build(&sigs);

        assert!(pf.always_run().is_empty(), "left to run on everything");
        assert!(pf.candidates("host LINUX 6.1.0").contains(&0));
        assert!(pf.candidates("host linux 6.1.0").contains(&0));
        assert!(pf.candidates("host FreeBSD 14.1").is_empty());
    }

    /// A `k` under `(?i)` also matches the Kelvin sign, which no ASCII-folded
    /// literal finds, so it is not read as a literal and a response spelling
    /// it that way is still selected.
    #[test]
    fn a_letter_whose_class_is_wider_than_its_two_cases_is_not_read_as_a_literal() {
        let pattern = r"(?i)^.{0,8}kernel";
        let response = "\u{212A}ERNEL";
        assert!(
            regex::Regex::new(pattern)
                .expect("compiles")
                .is_match(response),
            "the Kelvin sign is a k to the pattern"
        );

        let pf = LiteralPrefilter::build(&[sig(pattern)]);
        assert!(pf.candidates(response).contains(&0));
    }

    /// An alternation every branch of which holds a literal guarantees one of
    /// them, wherever in the pattern it stands.
    #[test]
    fn a_required_alternation_narrows_by_its_branches() {
        let sigs = [sig(r"^(.{0,16}) (?:Junos|ScreenOS) ([\d.]+)$")];
        let pf = LiteralPrefilter::build(&sigs);

        assert!(pf.always_run().is_empty(), "left to run on everything");
        assert!(pf.candidates("fw1 ScreenOS 6.3").contains(&0));
        assert!(pf.candidates("r1 Junos 23.4").contains(&0));
        assert!(pf.candidates("r1 IOS 15.2").is_empty());
    }

    proptest! {
        /// Candidate selection scans arbitrary response text through the
        /// Aho-Corasick automaton; it must never panic on any input, including
        /// non-ASCII and control characters.
        #[test]
        fn candidates_never_panics_on_arbitrary_input(response in "(?s).*") {
            let sigs = [sig(r"^HTTP/\d"), sig(r"Server: (\w+)"), sig(r"^\d{3} ")];
            let pf = LiteralPrefilter::build(&sigs);
            let _ = pf.candidates(&response);
        }
    }
}
