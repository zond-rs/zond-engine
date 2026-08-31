// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A settings document, and what applying one does to a configuration.
//!
//! The file here is the one nobody looks at: `engine.toml` synced out of a team
//! repository, or sitting in a home directory on a shared host. `import::settings`
//! argues that this is safe because there is nothing in the grammar worth
//! attacking — no include, no path that gets opened, no command — which makes
//! the parser and the layering the whole of the attack surface, and worth
//! covering.
//!
//! Parsing is only half of it. A document that parses still has to resolve to a
//! profile and then change a [`ZondConfig`], and the names it resolves under are
//! the fuzzer's own, so `resolve` is driven with the profiles the document
//! declares rather than with one written here.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::config::ZondConfig;
use zond_engine::import::settings;

/// How many of a document's profiles are resolved.
///
/// A file naming ten thousand of them is a file the parser has already accepted;
/// resolving every one would spend the run on repetition rather than on reaching
/// a new shape.
const PROFILES: usize = 8;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Ok(loaded) = settings::parse(text) else {
        return;
    };

    // What the caller is told it did not understand, which is the one thing a
    // silently-ignored key would cost.
    let _ = loaded.warnings.len();

    let named: Vec<String> = loaded
        .document
        .profile_names()
        .take(PROFILES)
        .map(str::to_owned)
        .collect();

    // The defaults on their own, then each profile layered over them, which is
    // the order `settings::resolve` applies to a real file.
    let profiles = std::iter::once(None).chain(named.iter().map(|name| Some(name.as_str())));

    for profile in profiles {
        let Ok(settings) = loaded.document.resolve(profile) else {
            continue;
        };

        let _ = settings.ports();

        let mut config = ZondConfig::default();
        settings.apply_to(&mut config);
    }
});
