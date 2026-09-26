// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A flow's patterns, compiled once and matched in one place
//!
//! A flow matches its `expect`, `bind` and `until` patterns against every reply
//! it reads, on the blocking thread it holds the port's socket on. Compiled at
//! each match, a pattern costs its compile every time and one copy of itself
//! per flow running at once; compiled once but matched on those threads, it
//! keeps a search cache for every thread that ever matched with it, for as
//! long as it is kept. So a pattern is compiled once for the process, keyed by
//! its source, and every match is made on one thread kept for flow matching,
//! where it has one cache.
//!
//! That thread is the flows' own rather than the one service identification
//! matches on. A flow reads under a wall-clock budget, and a match queued
//! behind a scan's identifications would spend it waiting; a flow's patterns
//! are few and each match takes microseconds, so the flows queue only behind
//! one another.
//!
//! The shipped flows hold about a hundred distinct patterns, and a caller's own
//! flows add theirs. The kept set is bounded all the same, at
//! [`MAX_KEPT_PATTERNS`], past which a pattern is compiled for its match and
//! dropped after it, so a process loading flows without end does not keep
//! every pattern it ever saw.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use crate::fingerprint::MAX_COMPILED_REGEX_BYTES;
use crate::fingerprint::pattern::{self, CompiledPattern};

/// How many distinct patterns are kept compiled, ten times what the shipped
/// flows hold.
const MAX_KEPT_PATTERNS: usize = 1024;

/// `source` compiled, the one copy this process keeps, or `None` where it will
/// not compile. A refusal is kept too, so a pattern that will not compile is
/// tried once.
fn compiled(source: &str) -> Option<Arc<CompiledPattern>> {
    type Kept = HashMap<Box<str>, Option<Arc<CompiledPattern>>>;
    static KEPT: OnceLock<Mutex<Kept>> = OnceLock::new();

    let kept = KEPT.get_or_init(Mutex::default);
    // A panic while the map was held leaves it whole: an insert either landed
    // or did not, so the map is read on regardless.
    if let Some(found) = kept
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(source)
    {
        return found.clone();
    }

    // Compiled without the lock held, since a compile takes milliseconds and
    // every flow's matching waits on the lock. Two flows compiling one pattern
    // at once both compile it, and the first to finish is the one kept.
    let fresh = pattern::compile(source, MAX_COMPILED_REGEX_BYTES)
        .ok()
        .map(Arc::new);
    let mut kept = kept.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(found) = kept.get(source) {
        return found.clone();
    }
    if kept.len() < MAX_KEPT_PATTERNS {
        kept.insert(source.into(), fresh.clone());
    }
    fresh
}

/// A pattern compiled once for the process; see [`compiled`].
pub(crate) struct KeptPattern(Arc<CompiledPattern>);

impl KeptPattern {
    /// `source` compiled, or `None` where it will not compile.
    pub(crate) fn of(source: &str) -> Option<Self> {
        compiled(source).map(Self)
    }

    /// What `with` makes of the pattern, run on the flow-matching thread.
    pub(crate) fn matching<T: Send>(&self, with: impl FnOnce(&CompiledPattern) -> T + Send) -> T {
        on_the_matching_thread(|| with(&self.0))
    }
}

/// Runs `work` on the thread kept for flow matching, blocking the caller until
/// it is done, and hands back what it returns.
///
/// Run in place where that thread could not be started, which costs memory
/// and nothing else, and in place when called on it. A panic in `work`
/// reaches the caller as it would have in place.
fn on_the_matching_thread<T: Send>(work: impl FnOnce() -> T + Send) -> T {
    static POOL: OnceLock<Option<rayon::ThreadPool>> = OnceLock::new();

    let pool = POOL.get_or_init(|| {
        rayon::ThreadPoolBuilder::new()
            .num_threads(1)
            .thread_name(|_| "zond-flow-match".to_string())
            .build()
            .ok()
    });
    match pool {
        Some(pool) => pool.install(work),
        None => work(),
    }
}

/// What `with` makes of `source` compiled, run on the flow-matching thread,
/// or `None` where the pattern will not compile.
pub(crate) fn matching<T: Send>(
    source: &str,
    with: impl FnOnce(&CompiledPattern) -> T + Send,
) -> Option<T> {
    Some(KeptPattern::of(source)?.matching(with))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A pattern is compiled once for the process, however many flows and
    /// replies match with it, and one that will not compile is refused each
    /// time without being kept as anything else.
    #[test]
    fn a_pattern_is_compiled_once_for_the_process() {
        let first = compiled("^OK kept once").expect("compiles");
        let again = compiled("^OK kept once").expect("compiles");
        assert!(Arc::ptr_eq(&first, &again), "compiled twice");

        assert!(compiled("(unclosed").is_none());
        assert!(compiled("(unclosed").is_none());
    }

    /// Every match is made on the one flow-matching thread, from whichever
    /// thread a flow runs on, so a pattern keeps one search cache and not one
    /// per thread that ever matched with it.
    #[test]
    fn every_match_is_made_on_the_flow_matching_thread() {
        let threads: std::collections::BTreeSet<String> = (0..8)
            .map(|_| {
                std::thread::spawn(|| {
                    matching("^\\+OK", |_| format!("{:?}", std::thread::current().id()))
                        .expect("compiles")
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|thread| thread.join().expect("joins"))
            .collect();
        assert_eq!(threads.len(), 1, "matched on {threads:?}");
    }
}
