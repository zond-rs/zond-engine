// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A module's regular expressions, compiled once where that is affordable
//!
//! A module tends to name the same few patterns repeatedly, so a compiled
//! pattern is kept for the process, keyed by its source.
//!
//! A module's patterns may be built from reply bytes, so the kept set is
//! bounded by count, by source bytes, and by each pattern's compiled size. A
//! pattern past those bounds is compiled for its call only. The oldest leaves
//! when the set is full.
//!
//! Unlike flow patterns, these are matched on the caller's thread, since a
//! module's regex calls are paid from its own budget. Each thread then grows a
//! lazy search cache, bounded by [`MAX_COMPILED_BYTES`].

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use ::regex::{Error, Regex, RegexBuilder};

/// The most a module's pattern may compile to, and the ceiling on its lazy
/// search cache.
///
/// The linear engine bounds match time but not a huge pattern's program size.
const MAX_COMPILED_BYTES: usize = 1 << 20;

/// The most a kept pattern may compile to.
///
/// A header or version pattern compiles to a few kilobytes, a Unicode `\w+` to
/// under 64 KiB. A larger one compiles within [`MAX_COMPILED_BYTES`] for its
/// call alone.
const MAX_KEPT_COMPILED_BYTES: usize = 128 * 1024;

/// How many patterns are kept compiled, several times the regex calls the
/// shipped modules make between them.
///
/// With [`MAX_KEPT_COMPILED_BYTES`], this caps the set at 16 MiB of compiled
/// programs.
const MAX_KEPT_PATTERNS: usize = 128;

/// How many bytes of source the kept patterns may hold between them, the key
/// every lookup hashes.
const MAX_KEPT_SOURCE_BYTES: usize = 32 * 1024;

/// What became of compiling one pattern.
#[derive(Clone)]
enum Compiled {
    /// Compiled within the kept bound, and the copy every call matches with.
    Kept(Arc<Regex>),
    /// Compiles only past the kept bound, so it is compiled per call; remembered
    /// so the kept bound is not tried again.
    PerCall,
    /// Does not compile, and never will.
    Refused,
}

/// The compiled patterns kept, bounded as the module documentation says.
struct KeptPatterns {
    /// What each kept source compiled to.
    compiled: HashMap<Arc<str>, Compiled>,
    /// The kept sources, oldest first, the order they leave in.
    order: VecDeque<Arc<str>>,
    /// The bytes of source [`compiled`](Self::compiled) holds.
    source_bytes: usize,
}

impl KeptPatterns {
    /// A set holding nothing.
    fn new() -> Self {
        Self {
            compiled: HashMap::new(),
            order: VecDeque::new(),
            source_bytes: 0,
        }
    }

    /// `source` compiled, the kept copy where there is one, or `None` where it
    /// will not compile within [`MAX_COMPILED_BYTES`].
    ///
    /// Compiled without the lock; if two runs race, the first to finish is kept.
    fn get(this: &Mutex<Self>, source: &str) -> Option<Arc<Regex>> {
        // A poisoned set is still consistent; each change completes before the next.
        let lock = || this.lock().unwrap_or_else(PoisonError::into_inner);

        let found = lock().compiled.get(source).cloned();
        let compiled = match found {
            Some(compiled) => compiled,
            None => {
                let fresh = compile_to_keep(source);
                let mut kept = lock();
                match kept.compiled.get(source) {
                    Some(raced) => raced.clone(),
                    None => {
                        kept.insert(source, fresh.clone());
                        fresh
                    }
                }
            }
        };
        match compiled {
            Compiled::Kept(regex) => Some(regex),
            Compiled::PerCall => compile(source, MAX_COMPILED_BYTES).ok().map(Arc::new),
            Compiled::Refused => None,
        }
    }

    /// Keeps `compiled` for `source`, letting the oldest go until the set is
    /// back within its bounds. A source past the byte bound on its own is not
    /// kept at all.
    fn insert(&mut self, source: &str, compiled: Compiled) {
        if source.len() > MAX_KEPT_SOURCE_BYTES {
            return;
        }
        while self.compiled.len() >= MAX_KEPT_PATTERNS
            || self.source_bytes + source.len() > MAX_KEPT_SOURCE_BYTES
        {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            self.source_bytes -= oldest.len();
            self.compiled.remove(&oldest);
        }
        let source: Arc<str> = source.into();
        self.source_bytes += source.len();
        self.order.push_back(Arc::clone(&source));
        self.compiled.insert(source, compiled);
    }
}

/// `source` compiled under the kept bound, or the answer that says why it
/// cannot be kept.
fn compile_to_keep(source: &str) -> Compiled {
    match compile(source, MAX_KEPT_COMPILED_BYTES) {
        Ok(regex) => Compiled::Kept(Arc::new(regex)),
        Err(Error::CompiledTooBig(_)) => match compile(source, MAX_COMPILED_BYTES) {
            Ok(_) => Compiled::PerCall,
            Err(_) => Compiled::Refused,
        },
        Err(_) => Compiled::Refused,
    }
}

/// `source` compiled with its program and search cache bounded by `bytes`.
fn compile(source: &str, bytes: usize) -> Result<Regex, Error> {
    RegexBuilder::new(source)
        .size_limit(bytes)
        .dfa_size_limit(MAX_COMPILED_BYTES)
        .build()
}

/// A guest-supplied pattern compiled, the process's kept copy where it has
/// one, or [`None`] if it will not compile within [`MAX_COMPILED_BYTES`].
pub(super) fn guest_regex(source: &str) -> Option<Arc<Regex>> {
    static KEPT: OnceLock<Mutex<KeptPatterns>> = OnceLock::new();
    KeptPatterns::get(KEPT.get_or_init(|| Mutex::new(KeptPatterns::new())), source)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kept(set: &Mutex<KeptPatterns>, source: &str) -> Arc<Regex> {
        KeptPatterns::get(set, source).expect("compiles")
    }

    /// A pattern named again uses the first compiled copy.
    #[test]
    fn a_pattern_named_again_is_not_compiled_again() {
        let first = guest_regex("nginx/([0-9.]+)").expect("compiles");
        let again = guest_regex("nginx/([0-9.]+)").expect("compiles");
        assert!(Arc::ptr_eq(&first, &again), "compiled twice");

        assert!(guest_regex("(unclosed").is_none());
        assert!(guest_regex("(unclosed").is_none(), "a refusal stands");
    }

    /// The set stays within its count and keeps the latest patterns.
    #[test]
    fn the_set_holds_no_more_patterns_than_its_bound() {
        let set = Mutex::new(KeptPatterns::new());
        for n in 0..MAX_KEPT_PATTERNS + 10 {
            kept(&set, &format!("^p{n}$"));
        }
        let set = set.into_inner().expect("not poisoned");
        assert_eq!(set.compiled.len(), MAX_KEPT_PATTERNS);
        assert!(!set.compiled.contains_key("^p0$"), "the oldest left first");
        let latest = format!("^p{}$", MAX_KEPT_PATTERNS + 9);
        assert!(set.compiled.contains_key(latest.as_str()));
    }

    /// Long sources are held to the byte bound however few of them there are,
    /// and one longer than the whole bound still matches, uncached.
    #[test]
    fn the_set_holds_no_more_source_than_its_bound() {
        let set = Mutex::new(KeptPatterns::new());
        // Ignored padding: long to key on, small to compile.
        let long = |n: usize| format!("(?x){n}{}", " ".repeat(MAX_KEPT_SOURCE_BYTES / 4));
        for n in 0..8 {
            kept(&set, &long(n));
        }
        assert!(set.lock().expect("not poisoned").source_bytes <= MAX_KEPT_SOURCE_BYTES);

        let past = format!("(?x)b{}", " ".repeat(MAX_KEPT_SOURCE_BYTES));
        let first = kept(&set, &past);
        let again = kept(&set, &past);
        assert!(!Arc::ptr_eq(&first, &again), "kept past the bound");
        assert!(again.is_match("b"));
        assert!(set.lock().expect("not poisoned").source_bytes <= MAX_KEPT_SOURCE_BYTES);
    }

    /// A pattern past the kept bound but within the ceiling still matches.
    #[test]
    fn a_pattern_too_large_to_keep_still_matches() {
        let set = Mutex::new(KeptPatterns::new());
        // A Unicode class repeated compiles to a few hundred kilobytes.
        let large = r"\w{1,8}";
        assert!(
            compile(large, MAX_KEPT_COMPILED_BYTES).is_err(),
            "fits the kept bound"
        );
        let first = kept(&set, large);
        let again = kept(&set, large);
        assert!(!Arc::ptr_eq(&first, &again), "held past the kept bound");
        assert!(again.is_match("zond"));
    }
}
