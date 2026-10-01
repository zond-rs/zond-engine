// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Property tests for pattern compilation
//!
//! Kept apart from [`pattern`](super::pattern) because `build.rs` loads
//! `pattern.rs` with `#[path]`, and `proptest` is not a build dependency. Tools
//! reading that file in the build script's context would report the import as
//! unresolved; this module is declared only by the library.

use super::pattern::compile;
use proptest::prelude::*;

/// The compiled-size ceiling the runtime and the build both use.
const LIMIT: usize = 32 * 1024 * 1024;

proptest! {
    /// The backtrack-step limit makes the backtracking engine terminate on any
    /// input. A backref pattern forces that engine; the test completing shows
    /// no input hangs or panics.
    #[test]
    fn fancy_engine_matching_terminates_on_any_input(input in "(?s).*") {
        let compiled = compile(r"^(\w+)\s+\1$", LIMIT).unwrap();
        let _ = compiled.identify(&input, None);
}

    /// A pattern built for catastrophic backtracking stays bounded on all-`a`
    /// inputs of growing length.
    #[test]
    fn catastrophic_pattern_stays_bounded(len in 0usize..64) {
        let compiled = compile(r"(a+)+\1c", LIMIT).unwrap();
        let _ = compiled.identify(&"a".repeat(len), None);
}
}
