// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A module's regular expressions, compiled once where that is affordable
//!
//! A module names a pattern at each call of a regex helper, and a module
//! matching in a loop, or run over every port of a scan, names the same few
//! again and again. Compiled at each call, each costs its compile every time,
//! on the thread whose wall-clock budget the run is spending. So a compiled
//! pattern is kept for the process, keyed by its source, and every later call
//! naming it matches with that copy.
//!
//! A flow's patterns are kept the same way, but a flow's come from its
//! definition, while a module's are whatever its code computes, which may be
//! built from a reply the scan did not write. So this set is bounded by what it
//! holds and not only by how many: by count, by the bytes of source it keys on,
//! and by what each kept pattern may compile to. A pattern past those bounds is
//! compiled for its call and dropped after it. The oldest pattern leaves when
//! the set is full, so a module naming a new pattern at every call keeps the
//! set turning over rather than filling it once and leaving every pattern
//! named after that uncached.
//!
//! Matched on the caller's thread, unlike a flow's, which are matched on one
//! thread kept for them. A module's regex calls are part of its run and are
//! paid for from its budget, and a hop to a thread every module shares would
//! have each run wait on every other's matching. What that costs is a lazy
//! search cache per thread matching with a kept pattern at once, each grown
//! only as far as its searches need and never past
//! [`MAX_COMPILED_BYTES`]'s bound.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use ::regex::{Error, Regex, RegexBuilder};

/// The most a module's pattern may compile to, and the ceiling on its lazy
/// search cache.
///
/// The one cost of a guest pattern the linear engine does not bound itself: a
/// pathologically large pattern's compiled program, which is memory rather than
/// the runaway match time a backtracking engine would risk.
const MAX_COMPILED_BYTES: usize = 1 << 20;

/// The most a kept pattern may compile to.
///
/// Measured against the patterns a module writes: a header or version pattern
/// compiles to a few kilobytes, and a Unicode `\w+` to under 64 KiB. A pattern
/// needing more still compiles, within [`MAX_COMPILED_BYTES`], but for its call
/// alone.
const MAX_KEPT_COMPILED_BYTES: usize = 128 * 1024;

/// How many patterns are kept compiled, several times the regex calls the
/// shipped modules make between them.
///
/// With [`MAX_KEPT_COMPILED_BYTES`], this bounds what the set costs at 16 MiB
/// of compiled programs, whatever a module names.
const MAX_KEPT_PATTERNS: usize = 128;

/// How many bytes of source the kept patterns may hold between them, the key
/// every lookup hashes.
const MAX_KEPT_SOURCE_BYTES: usize = 32 * 1024;

/// What became of compiling one pattern.
#[derive(Clone)]
enum Compiled {
    /// Compiled within the kept bound, and the copy every call matches with.
    Kept(Arc<Regex>),
    /// Compiles only past the kept bound, so it is compiled for each call. Kept
    /// as that answer so the kept bound is not tried again.
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
    /// Compiled without the lock held, since a compile can take milliseconds
    /// and every module's regex call waits on the lock. Two runs compiling one
    /// pattern at once both compile it, and the first to finish is kept.
    fn get(this: &Mutex<Self>, source: &str) -> Option<Arc<Regex>> {
        // A panic while the set was held leaves it whole, since each change to
        // it completes before the next, so it is read on regardless.
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

    /// A pattern named again is matched with the copy compiled the first time,
    /// which is what spares a module matching in a loop a compile per call.
    #[test]
    fn a_pattern_named_again_is_not_compiled_again() {
        let first = guest_regex("nginx/([0-9.]+)").expect("compiles");
        let again = guest_regex("nginx/([0-9.]+)").expect("compiles");
        assert!(Arc::ptr_eq(&first, &again), "compiled twice");

        assert!(guest_regex("(unclosed").is_none());
        assert!(guest_regex("(unclosed").is_none(), "a refusal stands");
    }

    /// A module naming a new pattern at every call cannot grow the set past its
    /// count, and the patterns it keeps are the latest ones.
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
        // Padding a verbose pattern ignores, so each is long to key on and small
        // to compile.
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

    /// A pattern compiling past the kept bound, but within the ceiling, still
    /// matches, compiled for each call rather than held.
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
