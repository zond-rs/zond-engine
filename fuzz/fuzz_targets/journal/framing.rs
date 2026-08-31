// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A journal file, as something other than this engine left it.
//!
//! The framing is one record per line behind a header, and the reader is written
//! for a file that was being appended to when the process holding it died. It
//! has to tell a torn last line from a corrupt one, refuse a version it cannot
//! promise to read, and refuse a file that is not a journal at all — and a
//! journal sits in a state directory for a month, where an operator can edit it,
//! a disk can lose part of it, and a restore can put back half of one.
//!
//! ## The oracle: what a journal yields, it yields again
//!
//! Whatever the reader gets out of arbitrary bytes is written back through the
//! writer and read again, and the two sequences have to match. That is the
//! promise this format makes and the export DTOs deliberately do not — "this
//! side owns its data, promises to read what it wrote" — and it is the one a
//! resume rests on, because the records are what a second sitting starts from.
//!
//! Each record is also rebuilt into a `Host`, which is what `read_findings` does
//! with it. A record the reader accepts and the model cannot take is a journal
//! that opens and then brings down the scan continuing it.
//!
//! ## What is not asserted
//!
//! That a file the reader refuses is a file it should have refused. Reading down
//! to the framing, most inputs are not journals, and the interesting ones are
//! the near misses: a good header and a truncated record, a version one past
//! this build's, a blank line in the middle. `seeds/journal_framing` holds those
//! so the fuzzer starts from them rather than having to invent a header.

#![no_main]

use std::io::Cursor;

use libfuzzer_sys::fuzz_target;
use zond_engine::journal::format::{Reader, Writer};
use zond_engine::model::host::Host;
use zond_engine::record::HostRecord;

fuzz_target!(|data: &[u8]| {
    let Ok(mut reader) = Reader::open(Cursor::new(data)) else {
        return;
    };

    let mut records = Vec::new();
    let mut line = reader.line();
    loop {
        // Monotone, because a caller attaches it to an error it raises about a
        // record's contents and a number that went backwards would name the
        // wrong one.
        assert!(
            reader.line() >= line,
            "the reader's line number went backwards"
        );
        line = reader.line();

        match reader.read::<HostRecord>() {
            Ok(Some(record)) => {
                // What `read_findings` does with each one. A record the framing
                // accepts and the model cannot take is a journal that opens and
                // then fails the scan continuing it.
                let _ = Host::from(&record);
                records.push(record);
            }
            Ok(None) => break,
            // A whole line that does not parse is corruption and is reported.
            // The reader stops there and so does this.
            Err(_) => return,
        }
    }

    let mut rewritten = Vec::new();
    let mut writer = Writer::create(&mut rewritten).expect("a header this crate writes");
    for record in &records {
        writer
            .write(record)
            .expect("a record this crate just read has to be writable");
    }
    writer.flush().expect("flushing to a vector");

    let mut reread =
        Reader::open(Cursor::new(&rewritten[..])).expect("this crate's own journal has to open");
    let mut restored = Vec::new();
    while let Some(record) = reread
        .read::<HostRecord>()
        .expect("this crate's own records have to read back")
    {
        restored.push(record);
    }

    assert_eq!(
        records, restored,
        "a journal did not hold what it was told to hold"
    );
});
