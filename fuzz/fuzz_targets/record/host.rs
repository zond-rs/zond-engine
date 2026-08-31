// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! One host, across the boundary between the model and a file.
//!
//! `record` is where every field a scan establishes stops being a type with
//! invariants and becomes something a file can hold. Both directions are
//! hand-written — deliberately, and the module argues for it at length — so
//! nothing but a test says the two agree, and a field added to one and not the
//! other is silent.
//!
//! ## The oracle: the record is a fixed point
//!
//! Rebuilding a record into a `Host` and recording that host again must give
//! *the same record*, and doing it a second time must change nothing more.
//!
//! The first pass is where the disagreements are, and they are why the first
//! record is not what is compared. A record from a fuzzer says things the model
//! refuses: a status this build has no name for, three hundred thousand ports
//! against a cap, an OS claim past the evidence ceiling, a hardware address that
//! is not one. The rebuild reads all of that *downward*, to the least the engine
//! could have established, so the record that comes out is narrower than the one
//! that went in and rightly so.
//!
//! What must not happen is that it keeps narrowing. A second rebuild starts from
//! values the model has already accepted, and if the record moves again then one
//! of the two conversions is not the inverse of the other over its own output —
//! which is a journal that reads back as something else every time it is
//! resumed.
//!
//! ## And that the record survives the format it exists for
//!
//! A `HostRecord` is written as JSON and read back as one. Asserted after the
//! rebuild rather than on the fuzzer's own record, because the interesting
//! values are the ones the model produced.

#![no_main]

use libfuzzer_sys::fuzz_target;
use zond_engine::model::host::Host;
use zond_engine::record::HostRecord;

fuzz_target!(|data: &[u8]| {
    let Ok(record) = serde_json::from_slice::<HostRecord>(data) else {
        return;
    };

    // The narrowing pass: everything the model declines to accept is dropped or
    // read down here, and `settled` is the first record made only of values it
    // did accept.
    let host = Host::from(&record);
    let settled = HostRecord::from(&host);

    let rebuilt = Host::from(&settled);
    let again = HostRecord::from(&rebuilt);

    assert_eq!(
        settled, again,
        "recording a host, rebuilding it and recording it again moved the record"
    );

    let text = serde_json::to_string(&settled).expect("a record this crate built has to serialize");
    let read: HostRecord =
        serde_json::from_str(&text).expect("this crate's own record has to read back");

    assert_eq!(
        settled, read,
        "a record did not survive the format it exists for"
    );
});
