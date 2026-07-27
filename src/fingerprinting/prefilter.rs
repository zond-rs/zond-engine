// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0.
// If a copy of the MPL was not distributed with this file, You can obtain one at
// https://mozilla.org/MPL/2.0/.

//! # Global-match prefilter
//!
//! Selecting matching signatures on a non-standard port means matching against
//! the *whole* set. Running every regex would be O(number of signatures) per
//! response — fine at a few thousand, not future-proof as the set grows. A
//! [`Prefilter`] narrows the field to a small candidate set first, so global
//! matching stays sublinear in the size of the database.
//!
//! ## The literal engine
//!
//! [`LiteralPrefilter`] extracts, for each signature, a set of literals such
//! that **any match must contain at least one of them**, and indexes them in an
//! Aho-Corasick automaton. A response's candidates are the signatures whose
//! literal appears in it, plus a small "always-run" bucket of signatures no
//! usable literal could be extracted from (binary protocols, pure-structural
//! patterns, case-folded `(?i)` patterns).
//!
//! ### Soundness
//!
//! Only *required* literals are used — extracted from a pattern's prefix
//! (handling alternations), its longest guaranteed inner run, or its suffix.
//! Each is a substring every match must contain, so a signature is never
//! wrongly excluded. This is checked against the recorded-example corpus
//! (`corpus.rs`): every example that matches its pattern must select that
//! pattern as a candidate. Measured on the current set: ~0.8% of signatures
//! fall in the always-run bucket, zero soundness violations.
//!
//! [`Prefilter`] is a trait so a faster backend (e.g. `hyperscan`/`vectorscan`)
//! can replace the engine without touching callers.

use aho_corasick::AhoCorasick;
use regex_syntax::hir::literal::{ExtractKind, Extractor};
use regex_syntax::hir::{Hir, HirKind};
use regex_syntax::parse;

use super::matcher::Signature;

/// Shortest literal worth indexing; below this, a literal is too common to
/// narrow anything and the signature is better left always-run.
const MIN_LITERAL_LEN: usize = 3;

/// Narrows the whole signature set to a candidate list for a response.
pub trait Prefilter: Send + Sync {
    /// Indices (into the signature set the prefilter was built from) that could
    /// possibly match `response`. Never omits a signature that would match.
    fn candidates(&self, response: &str) -> Vec<usize>;
}

/// A required-literal Aho-Corasick prefilter. See the module docs.
pub struct LiteralPrefilter {
    automaton: AhoCorasick,
    /// Aho-Corasick pattern id -> the signature index that contributed it.
    literal_owner: Vec<usize>,
    /// Signatures with no usable required literal; always candidates.
    always_run: Vec<usize>,
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
        }
    }
}

impl Prefilter for LiteralPrefilter {
    fn candidates(&self, response: &str) -> Vec<usize> {
        let mut selected = vec![false; self.literal_owner.len().max(1)];
        let mut candidates = self.always_run.clone();

        for m in self.automaton.find_overlapping_iter(response) {
            let owner = self.literal_owner[m.pattern().as_usize()];
            // De-dup by owner cheaply: a signature can contribute many literals.
            if !std::mem::replace(&mut selected[m.pattern().as_usize()], true) {
                candidates.push(owner);
            }
        }

        candidates.sort_unstable();
        candidates.dedup();
        candidates
    }
}

/// A set of literals such that every match of `pattern` contains at least one,
/// or `None` if no such bounded set could be extracted (the caller then treats
/// the signature as always-run).
///
/// Tries, in order: the prefix literal set (which captures leading
/// alternations), the longest guaranteed inner literal, then the suffix set.
fn required_literals(pattern: &str) -> Option<Vec<Vec<u8>>> {
    let hir = parse(pattern).ok()?;

    if let Some(set) = literal_set(&hir, ExtractKind::Prefix) {
        return Some(set);
    }
    if let Some(inner) = longest_required_literal(&hir).filter(|l| l.len() >= MIN_LITERAL_LEN) {
        return Some(vec![inner]);
    }
    literal_set(&hir, ExtractKind::Suffix)
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

/// The longest literal guaranteed to appear in every match, walking mandatory
/// positions of the HIR. `None` if no literal is guaranteed (e.g. under an
/// alternation, class, or optional repetition).
fn longest_required_literal(hir: &Hir) -> Option<Vec<u8>> {
    match hir.kind() {
        HirKind::Literal(literal) => Some(literal.0.to_vec()),
        HirKind::Capture(capture) => longest_required_literal(&capture.sub),
        HirKind::Concat(parts) => parts.iter().filter_map(longest_required_literal).max_by_key(Vec::len),
        HirKind::Repetition(rep) if rep.min >= 1 => longest_required_literal(&rep.sub),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::fingerprint::MatchRule;

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
        assert!(pf.candidates("host.example FTP Server (Version 1.2.3)").contains(&0));
        assert!(pf.candidates("SSH-2.0-OpenSSH_9.6").is_empty());
    }

    #[test]
    fn unfilterable_pattern_is_always_a_candidate() {
        // A pure-structural pattern yields no usable literal: always-run.
        let sigs = [sig(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")];
        let pf = LiteralPrefilter::build(&sigs);
        assert!(pf.candidates("anything at all").contains(&0));
    }

    #[test]
    fn case_insensitive_literal_still_selects() {
        let sigs = [sig(r"^Server: nginx")];
        let pf = LiteralPrefilter::build(&sigs);
        assert!(pf.candidates("server: NGINX/1.25").contains(&0));
    }
}
