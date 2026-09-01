// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Internal diagnostics
//!
//! How the engine's own code emits diagnostic events. Every macro here is
//! `pub(crate)`, and that is the whole of its API design.
//!
//! A library must not export these. Exported from the crate root they would
//! be `zond_engine::info!` and `zond_engine::error!`: five of the most generic
//! identifiers in Rust, shadowing `tracing`'s and `log`'s macros of the same
//! names in any consumer that glob-imports this crate, and pinned by semver
//! forever. Worse, a macro expanding to `tracing::info!` resolves that path in
//! the *caller's* namespace: a consumer who does not happen to depend on
//! `tracing` themselves gets a compile error out of a macro they were invited to
//! use. Neither problem is reachable from inside this repository, which is why
//! the expansions here are absolute (`::tracing::`) and the macros are not
//! exported.
//!
//! What a consumer sees instead is the events. The engine emits `tracing` and
//! installs no subscriber, so whoever embeds it decides whether anything is
//! rendered and how.
//!
//! Two fields carry the conventions a front end reads. `status` names what kind
//! of thing an event is, which is what a terminal colours on and a structured
//! consumer filters on. `verbosity` is set by the caller on anything below a
//! headline: a default run shows none of it.

macro_rules! info {
    (incoming, $($arg:tt)+) => {
        ::tracing::info!(status = "incoming", $($arg)+)
    };
    (outgoing, $($arg:tt)+) => {
        ::tracing::info!(status = "outgoing", $($arg)+)
    };
    ($($arg:tt)+) => {
        ::tracing::info!(status = "info", $($arg)+)
    };
}

macro_rules! success {
    ($($arg:tt)+) => {
        ::tracing::info!(status = "success", $($arg)+)
    };
}

macro_rules! error {
    ($($arg:tt)+) => {
        ::tracing::error!(status = "error", $($arg)+)
    };
}

// Defined under a name nothing else claims, then re-exported as `warn` below.
// `warn` is a built-in attribute, so re-exporting a macro of that name by its
// own name is ambiguous and will not compile; renaming on the way out resolves
// an unambiguous path and still binds the name every call site writes.
macro_rules! warn_macro {
    ($($arg:tt)+) => {
        ::tracing::warn!(status = "warn", $($arg)+)
    };
}

pub(crate) use error;
pub(crate) use info;
pub(crate) use success;
pub(crate) use warn_macro as warn;

// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    /// Every diagnostic in the crate is written in one voice.
    ///
    /// Lower case to begin with, and no full stop at the end: the way `rustc`
    /// and `cargo` write theirs, and the way the front end writes its own. A
    /// stream carrying `root privileges detected` beside `Successfully
    /// initialized hostname resolver` has two authors and reads like it.
    ///
    /// An initialism keeps its capitals. `DNS resolution skipped` is not a
    /// sentence beginning with a capital, it is a sentence beginning with a
    /// name, so the rule is that the first *word* must not be capitalised unless
    /// it is capitalised throughout.
    ///
    /// This reads the source because there is nowhere else to read it: the
    /// messages are string literals scattered across the crate, and a convention
    /// nothing checks is a convention that drifts. Twenty of thirty-one had
    /// drifted by the time anybody looked.
    #[test]
    fn every_diagnostic_is_written_in_one_voice() {
        const MACROS: [&str; 4] = ["info!", "success!", "warn!", "error!"];

        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut checked = 0;

        for file in sources(&root) {
            // The file that defines the macros quotes their own `status` names,
            // which are not messages.
            if file.file_name().is_some_and(|name| name == "logging.rs") {
                continue;
            }

            let text = std::fs::read_to_string(&file).expect("a source file");

            for (at, _) in MACROS.iter().flat_map(|name| text.match_indices(name)) {
                let Some(message) = literal_after(&text, at) else {
                    continue;
                };
                let Some(first) = message.split_whitespace().next() else {
                    continue;
                };

                // A `status` name, or a format argument, rather than a message.
                if message.len() < 4 || message.starts_with('{') {
                    continue;
                }

                checked += 1;
                let shouts = first
                    .chars()
                    .all(|c| !c.is_alphabetic() || c.is_uppercase());
                assert!(
                    !first.chars().next().is_some_and(char::is_uppercase) || shouts,
                    "{}: '{message}' begins with a capital that is not an initialism",
                    file.display()
                );
                assert!(
                    !message.trim_end().ends_with('.'),
                    "{}: '{message}' ends with a full stop",
                    file.display()
                );
            }
        }

        assert!(checked > 20, "the scan found only {checked} messages");
    }

    /// Every `.rs` file under `root`.
    fn sources(root: &std::path::Path) -> Vec<std::path::PathBuf> {
        let mut found = Vec::new();
        let Ok(entries) = std::fs::read_dir(root) else {
            return found;
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                found.extend(sources(&path));
            } else if path.extension().is_some_and(|kind| kind == "rs") {
                found.push(path);
            }
        }

        found
    }

    /// The first string literal after `at`, with its line continuations closed
    /// up. `None` where the call carries no literal at all.
    fn literal_after(text: &str, at: usize) -> Option<String> {
        let opening = text[at..].find('"')? + at + 1;
        let mut message = String::new();
        let mut chars = text[opening..].chars();

        while let Some(character) = chars.next() {
            match character {
                '"' => return Some(message),
                '\\' => match chars.next() {
                    // A line continuation: the newline and the indent after it
                    // are not part of the message.
                    Some('\n') => {
                        while chars.clone().next().is_some_and(char::is_whitespace) {
                            chars.next();
                        }
                    }
                    Some(escaped) => message.push(escaped),
                    None => return None,
                },
                _ => message.push(character),
            }
        }

        None
    }
}
