// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! The readers behind `ImportFormat::read`: a target list, a spreadsheet, a
//! report read back for the hosts it names.
//!
//! These are the files an operator is handed rather than the ones this engine
//! wrote — a scope document from a client, an asset export from a CMDB, a list
//! pasted out of a ticket — and every one of them arrives as a target set that
//! decides what gets probed. A reader that mangles one produces a scan of
//! something other than what was asked for, and nothing downstream says so.
//!
//! The list grammar and the CSV record reader with its quoting, its carriage
//! returns and its formula guard had no coverage here at all.
//!
//! **Sniffing runs against the same bytes as the reader.** Guessing a format and
//! then reading it are two answers to one question, and they are supposed to
//! agree: a document `sniff` calls JSON is one the JSON reader can at least
//! begin. They disagreed on any file a Windows editor saved, which is what this
//! arm is here to keep from coming back.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::import::{ImportFormat, ImportLimits, ImportOptions, OnRefusal};
use zond_engine::model::port::PortSet;

fuzz_target!(|data: &[u8]| {
    let Some((selector, document)) = data.split_first() else {
        return;
    };

    // The address ceiling is lowered from the default whole of IPv4. The bound
    // is still exercised — a fuzzer reaches a refusal in one short line — but no
    // input can ask this process to account for four billion addresses, and to a
    // fuzzer a slow input and a hung one are the same finding.
    let options = ImportOptions::new(PortSet::try_from("80,u:53").expect("a constant port set"))
        .with_limits(ImportLimits::default().with_max_addresses(1 << 20))
        .with_refusal_policy(if selector & 1 == 0 {
            OnRefusal::Abort
        } else {
            OnRefusal::Collect
        });

    // The format the caller was told the file is. Chosen from the input so the
    // fuzzer can steer, rather than round-robined, which would spend seven
    // eighths of every interesting document on readers that refuse it at once.
    let formats = ImportFormat::all();
    let format = formats[usize::from(selector >> 1) % formats.len()];

    if let Ok(imported) = format.read(&mut Cursor::new(document), &options) {
        // Abort is the default and its whole promise is that it does not carry
        // on: a refusal it collected would be a bad expression the caller was
        // never told about, in an import that reported success.
        if selector & 1 == 0 {
            assert!(
                imported.refusals.is_empty(),
                "an import that aborts on the first refusal returned {} of them",
                imported.refusals.len()
            );
        }

        assert!(
            imported.refusals.len() as u64 <= imported.tokens,
            "more expressions were refused than were read"
        );

        // `addresses` counts once per unit an address appears in, and the fold
        // to a sweep merges those, so the merged set can only be smaller. The
        // inequality is what says the two counts are answers to the same
        // question — a fold that lost a whole unit would break it.
        let counted = imported.addresses;
        let swept = imported.into_ip_set().len();
        assert!(
            swept <= counted,
            "a sweep of {swept} addresses came out of {counted} that were counted"
        );
    }

    // And the format this crate works out for itself, on the same bytes.
    let mut input = Cursor::new(document);
    if let Ok(sniffed) = ImportFormat::sniff(&mut input) {
        let _ = sniffed.read(&mut input, &options);
    }
});
