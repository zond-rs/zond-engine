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
//!
//! ## What each `verbosity` holds
//!
//! A front end maps its own verbosity setting onto the field, so each level is
//! a promise about what is found there, and a line goes to the level its reader
//! is at:
//!
//! | `verbosity` | Holds | For example |
//! |---|---|---|
//! | none | what the run is doing, and anything to act on | the privilege it runs with, a strategy that failed |
//! | 1 | the decisions behind this result | the link a sweep covers, where extra candidates came from, what went uncovered and why, which resolvers are asked, what named a host |
//! | 2 | a line per host or per exchange | a reverse query and its answer, a trace, a target with no route |
//! | 3 | the engine's working, for debugging it | capture filters, strategy spawns, the audit counters a report also carries |
//!
//! A line that repeats per host belongs at 2 however interesting it is. And a
//! function that answers a question does not narrate its answer: whoever acts
//! on it says so, once.

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

/// A count and the noun it counts, in the form that count takes: `1 host`,
/// `2 hosts`.
///
/// Both forms are named rather than an `s` appended, because English does not
/// append one to every noun and the next message to want this may be counting
/// entries or replies. Taking `u128` rather than `usize` is what lets one
/// function serve a target count, a dropped-frame counter and a slice length
/// without any of them being narrowed on the way in.
///
/// Never `host(s)`: the count is in hand wherever a message is written, and a
/// hedged plural is the scanner declining to answer a question it already
/// knows the answer to.
pub(crate) fn counted(count: u128, one: &str, many: &str) -> String {
    match count {
        1 => format!("1 {one}"),
        _ => format!("{count} {many}"),
    }
}

/// One event a closure emitted, as a front end reads it.
#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Logged {
    /// The event's level. A front end shows an error whatever its verbosity,
    /// so a line meant for a reader who asked for detail is not one.
    pub(crate) level: tracing::Level,
    /// The `verbosity` field, 0 for a line a default run shows.
    pub(crate) verbosity: u64,
    /// The formatted message.
    pub(crate) message: String,
}

#[cfg(test)]
impl tracing::field::Visit for Logged {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{value:?}");
        }
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "verbosity" {
            self.verbosity = value;
        }
    }
    // An unsuffixed literal is recorded signed.
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if field.name() == "verbosity" {
            self.verbosity = u64::try_from(value).unwrap_or(u64::MAX);
        }
    }
}

/// The events `run` emits on this thread, with the verbosity each was given,
/// which is what decides whether a default console shows it.
#[cfg(test)]
pub(crate) fn logged(run: impl FnOnce()) -> Vec<Logged> {
    use std::sync::{Arc, Mutex};
    use tracing::span::{Attributes, Id, Record};

    struct Recorder(Arc<Mutex<Vec<Logged>>>);

    impl tracing::Subscriber for Recorder {
        fn enabled(&self, _: &tracing::Metadata<'_>) -> bool {
            true
        }
        fn new_span(&self, _: &Attributes<'_>) -> Id {
            Id::from_u64(1)
        }
        fn record(&self, _: &Id, _: &Record<'_>) {}
        fn record_follows_from(&self, _: &Id, _: &Id) {}
        fn event(&self, event: &tracing::Event<'_>) {
            let mut logged = Logged {
                level: *event.metadata().level(),
                verbosity: 0,
                message: String::new(),
            };
            event.record(&mut logged);
            self.0
                .lock()
                .unwrap_or_else(|held| held.into_inner())
                .push(logged);
        }
        fn enter(&self, _: &Id) {}
        fn exit(&self, _: &Id) {}
    }

    let lines = Arc::new(Mutex::new(Vec::new()));
    tracing::subscriber::with_default(Recorder(Arc::clone(&lines)), run);
    lines
        .lock()
        .unwrap_or_else(|held| held.into_inner())
        .clone()
}

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
    /// An initialism keeps its capitals. `DNS queries skipped` is not a
    /// sentence beginning with a capital, it is a sentence beginning with a
    /// name, so the rule is that the first *word* must not be capitalised unless
    /// it is capitalised throughout.
    ///
    /// Nor does a message hedge a plural as `host(s)`. The count is in hand at
    /// the point the message is written, so the noun takes the form that count
    /// gives it; [`counted`] is what writes both.
    ///
    /// This reads the source because there is nowhere else to read it: the
    /// messages are string literals scattered across the crate, and a convention
    /// nothing checks is a convention that drifts.
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
                assert!(
                    !message.contains("(s)"),
                    "{}: '{message}' hedges a plural; count it and use `counted`",
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
