// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A flow's patterns, compiled once and matched in one place
//!
//! A pattern is compiled once for the process, keyed by its source, and every
//! match runs on one thread kept for flow matching, so each pattern keeps one
//! search cache rather than one per thread.
//!
//! That thread is separate from service identification's, since a flow runs
//! under a wall-clock budget and should not queue behind identifications.
//!
//! The shipped flows hold about a hundred distinct patterns. Past
//! [`MAX_KEPT_PATTERNS`] a pattern is compiled for its match and dropped.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};

use crate::fingerprint::MAX_COMPILED_REGEX_BYTES;
use crate::fingerprint::pattern::{self, CompiledPattern};

/// How many distinct patterns are kept compiled, ten times what the shipped
/// flows hold.
const MAX_KEPT_PATTERNS: usize = 1024;

/// `source` compiled, the one copy this process keeps, or `None` where it will
/// not compile. Refusals are kept too.
fn compiled(source: &str) -> Option<Arc<CompiledPattern>> {
    type Kept = HashMap<Box<str>, Option<Arc<CompiledPattern>>>;
    static KEPT: OnceLock<Mutex<Kept>> = OnceLock::new();

    let kept = KEPT.get_or_init(Mutex::default);
    // A poisoned map is still consistent: an insert either landed or did not.
    if let Some(found) = kept
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .get(source)
    {
        return found.clone();
    }

    // Compiled without the lock; if two flows race, the first to finish is kept.
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
        #[cfg(test)]
        MATCHED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(Arc::as_ptr(&self.0) as usize);
        on_the_matching_thread(|| with(&self.0))
    }
}

/// The kept copies [`KeptPattern::matching`] has matched with, by address,
/// for [`matched_as_kept`].
#[cfg(test)]
static MATCHED: Mutex<Vec<usize>> = Mutex::new(Vec::new());

/// Whether a match has been made with the one copy of `source` this process
/// keeps, through [`KeptPattern::matching`].
///
/// Lets a test tell a call site using the kept path from one compiling its own
/// copy, which otherwise behave identically.
#[cfg(test)]
pub(crate) fn matched_as_kept(source: &str) -> bool {
    compiled(source).is_some_and(|kept| {
        MATCHED
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&(Arc::as_ptr(&kept) as usize))
    })
}

/// Runs `work` on the thread kept for flow matching, blocking the caller until
/// it is done, and hands back what it returns.
///
/// Runs in place when already on that thread or where it could not be started.
/// A panic in `work` reaches the caller.
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

    /// A pattern is compiled once; one that will not compile is refused each
    /// time.
    #[test]
    fn a_pattern_is_compiled_once_for_the_process() {
        let first = compiled("^OK kept once").expect("compiles");
        let again = compiled("^OK kept once").expect("compiles");
        assert!(Arc::ptr_eq(&first, &again), "compiled twice");

        assert!(compiled("(unclosed").is_none());
        assert!(compiled("(unclosed").is_none());
    }

    /// Every match runs on the one flow-matching thread.
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
