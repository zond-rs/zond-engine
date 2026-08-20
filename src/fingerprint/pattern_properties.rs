// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Property tests for pattern compilation
//!
//! Apart from [`pattern`](super::pattern) itself, and only because of where that
//! file has to live.
//!
//! `build.rs` loads `pattern.rs` with `#[path]`, so the build script compiles the
//! very same source the library does — which is what stops the patterns the build
//! validates from drifting away from the patterns the engine can match. The build
//! script's dependency set is its own, though, and `proptest` is a
//! dev-dependency that is not in it. Cargo strips `#[cfg(test)]` before the build
//! script is compiled so nothing breaks, but any tool reading that file in the
//! build script's context sees an import it cannot resolve, and reports it.
//!
//! Keeping the property tests here rather than there costs nothing and removes
//! that: this module is declared only by the library, so the build script never
//! sees it at all.

use super::pattern::compile;
use proptest::prelude::*;

/// The compiled-size ceiling the runtime and the build both use.
const LIMIT: usize = 32 * 1024 * 1024;

proptest! {
    /// The backtracking engine must *terminate* on any input — the
    /// backtrack-step limit is what guarantees it. This drives a backref
    /// pattern (which forces the fancy engine) against arbitrary strings; the
    /// test completing at all is the evidence that no input hangs or panics.
    #[test]
    fn fancy_engine_matching_terminates_on_any_input(input in "(?s).*") {
        let compiled = compile(r"^(\w+)\s+\1$", LIMIT).unwrap();
        let _ = compiled.identify(&input, None);
}

    /// Even a pattern built for catastrophic backtracking stays bounded: fed
    /// adversarial all-`a` inputs of growing length, each match still returns.
    #[test]
    fn catastrophic_pattern_stays_bounded(len in 0usize..64) {
        let compiled = compile(r"(a+)+\1c", LIMIT).unwrap();
        let _ = compiled.identify(&"a".repeat(len), None);
}
}
