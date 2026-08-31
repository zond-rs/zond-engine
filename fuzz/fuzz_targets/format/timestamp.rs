// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The timestamp both directions agree on, over text nobody shaped.
//!
//! `format::time` states that [`rfc3339`] and [`parse_rfc3339`] are inverses and
//! that the parser is "no more permissive than it needs to be". The property
//! test beside them only ever feeds the parser strings the writer produced,
//! which is the half that was already right: the shapes that got through were
//! ones no writer emits. A negative hour parsed and moved the moment into the
//! previous day, and `2026-02-31` parsed as the third of March — each a
//! perfectly ordinary-looking timestamp naming the wrong one.
//!
//! That matters where the parser is reached from, which is a report rebuilt out
//! of a file somebody else wrote. A `cert_not_after` off by a day is an expiry
//! alert on the wrong date; off by a month is one that never fires.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::format::time::{local, parse_rfc3339, rfc3339};

/// `YYYY-MM-DDTHH:MM:SS.ssssssZ`, which is the only shape the writer emits and
/// what makes two timestamps comparable as text.
const RENDERED_BYTES: usize = 27;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let Some(moment) = parse_rfc3339(text) else {
        return;
    };

    // Anything the parser accepts, the writer can write down — and in the one
    // shape the schema promises. A moment that reads back but renders wider or
    // narrower is one that stops sorting as text.
    let rendered = rfc3339(moment);
    assert_eq!(
        rendered.len(),
        RENDERED_BYTES,
        "'{text}' parsed and rendered as '{rendered}'"
    );

    // And what the writer wrote down reads back as itself. Rendering truncates
    // to microseconds, so the fixed point is reached after the first rendering
    // rather than before it: this says the second pass moves nothing.
    let reread = parse_rfc3339(&rendered)
        .unwrap_or_else(|| panic!("'{rendered}' was written and cannot be read back"));
    assert_eq!(
        rfc3339(reread),
        rendered,
        "'{text}' does not survive a second pass"
    );

    // The reader-facing rendering shares the calendar arithmetic and nothing
    // else, and it reaches a timezone database this crate does not own.
    let _ = local(moment);
});
