// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The journal's on-disk format
//!
//! One record per line, the first of which describes the file. The framing, the
//! version bargain, and the vocabulary shared with the export path.
//!
//! ## Why this is a promised format and the export DTOs are not
//!
//! [`export::schema`](crate::export::schema) is write-only by construction:
//! `&'a str` for every borrowed field, `&'static str` for every enum name,
//! nothing for `serde` to deserialize *into*. That is a deliberate choice and a
//! good one — it costs the export path no allocation per enum name per port —
//! and it is why `import::json` reads back only the four
//! fields a rescan needs and skips the rest without building it.
//!
//! A journal cannot make that trade. Resuming means reconstructing what the
//! first sitting found, in full, or the merged report silently loses it. So
//! this side owns its data, promises to read what it wrote, and carries a
//! version to say which shape it wrote it in.
//!
//! ## The bargain, which is the export document's
//!
//! - **Unknown fields are ignored.** A journal from a newer build stays
//!   readable for whatever it has in common with this one.
//! - **An unknown enum string reads downward.** A value this build does not
//!   recognise is not a field a reader can skip: it is the thing that decides
//!   what the record *says*. It is also one field of one host in a file holding
//!   a scan that took hours, and refusing the whole journal over it would throw
//!   that away for the same reason the torn last line below does not. So it is
//!   read as the weakest value the type has — a port state as `Filtered`, a
//!   sitting as a discovery sweep, a severity as `Info` — never as a stronger
//!   one, and never as a neighbour. [`record`](crate::record) makes that choice
//!   field by field and documents each; the parsers themselves guess at nothing
//!   and hand back [`None`].
//! - **[`JOURNAL_VERSION`] is required and checked.** A journal from a future
//!   major version is refused rather than read approximately, because by
//!   construction its positions may not mean what this build thinks.
//! - **A torn final line is discarded, not an error.** The writer appends and
//!   does not fsync per record (see [`journal`](super)), so a process killed
//!   mid-append leaves a partial last line. That is one record inside the replay
//!   interval, and refusing to open the file over it would throw away the six
//!   hours in front of it.
//!
//! ## Versioned apart from the export schema
//!
//! [`SCHEMA_VERSION`](crate::format::SCHEMA_VERSION) versions the report
//! document. This versions the journal. They answer different questions — "what
//! did this scan find" against "how do I continue this scan" — and coupling them
//! would mean an additive change to an export field invalidating every scan
//! currently in flight on disk.
//!
//! ## One vocabulary, both directions
//!
//! The wire names are [`record::wire`](crate::record::wire)'s, in both
//! directions and for every consumer, so a port state spells the same in a
//! report and in a journal and reads back the same from either. This module had
//! a `parse` of its own that re-exported six of them; it duplicated a public
//! path for no reader's benefit, was an arbitrary subset, and nothing but its
//! own tests ever called it.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::format::ENGINE_NAME;

#[doc(inline)]
pub use super::JOURNAL_VERSION;

/// What went wrong reading a journal.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The file did not begin with a header record, so it is not a journal this
    /// engine wrote — or it is empty.
    #[error("no journal header: this is not a file {ENGINE_NAME} wrote, or it is empty")]
    NotAJournal,

    /// The journal was written by a build whose format this one predates.
    #[error(
        "journal version {found} is newer than this build understands ({understood}); \
         resume it with the engine that wrote it"
    )]
    VersionTooNew {
        /// The version the file claims.
        found: u32,
        /// The newest version this build can read.
        understood: u32,
    },

    /// A record could not be parsed, and it was not the torn last line.
    #[error("journal line {line}: {message}")]
    Malformed {
        /// The 1-based line the failure is on.
        line: u64,
        /// What `serde` said about it.
        message: String,
    },

    /// The file could not be read or written.
    #[error("journal i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// The first line of every journal file, so a file read on its own says what it
/// is without a manifest beside it.
///
/// `engine` is recorded as well as the version because a journal is a file a
/// user may find in a state directory months later, and a document that cannot
/// name what produced it is a document nobody can act on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The format version, checked against [`JOURNAL_VERSION`] on open.
    pub journal_version: u32,
    /// Always [`ENGINE_NAME`].
    pub engine: String,
    /// The engine build that opened this journal, for diagnostics. **Not** a
    /// resume gate — the plan hash in the manifest is what refuses a resume
    /// whose meaning has moved.
    pub engine_version: String,
}

impl Header {
    /// The header this build writes.
    pub fn current() -> Self {
        Self {
            journal_version: JOURNAL_VERSION,
            engine: ENGINE_NAME.to_string(),
            engine_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

/// Writes records one per line, header first.
///
/// Appends and does not flush per record beyond what the underlying writer
/// does. Durability is the caller's policy, and [`journal`](super) documents
/// which failures that policy survives.
#[derive(Debug)]
pub struct Writer<W: Write> {
    inner: W,
}

impl<W: Write> Writer<W> {
    /// Begins a journal by writing its header.
    pub fn create(mut inner: W) -> Result<Self, JournalError> {
        writeln!(inner, "{}", serde_json::to_string(&Header::current())?)?;
        Ok(Self { inner })
    }

    /// Continues a journal that already carries a header, appending to it.
    ///
    /// No header is written and none is checked: a caller appending has already
    /// opened the file for reading and validated it, and re-validating here
    /// would mean this type needed the file to be seekable.
    pub fn append(inner: W) -> Self {
        Self { inner }
    }

    /// Appends one record.
    ///
    /// The newline is written after the record, so a process killed part way
    /// through leaves a line the reader discards rather than a line it
    /// misreads. See [`Reader`].
    pub fn write<T: Serialize>(&mut self, record: &T) -> Result<(), JournalError> {
        writeln!(self.inner, "{}", serde_json::to_string(record)?)?;
        Ok(())
    }

    /// Flushes the underlying writer.
    pub fn flush(&mut self) -> Result<(), JournalError> {
        self.inner.flush()?;
        Ok(())
    }
}

impl From<serde_json::Error> for JournalError {
    fn from(error: serde_json::Error) -> Self {
        JournalError::Malformed {
            line: 0,
            message: error.to_string(),
        }
    }
}

/// Reads a journal written by [`Writer`], validating its header on open.
#[derive(Debug)]
pub struct Reader<R: BufRead> {
    inner: R,
    line: u64,
    /// Set once a line arrived without a trailing newline. Everything after
    /// that point is a torn write, so the reader stops rather than guessing.
    truncated: bool,
}

impl<R: BufRead> Reader<R> {
    /// Opens a journal, reading and checking its header.
    ///
    /// Fails with [`JournalError::NotAJournal`] on an empty file or one whose
    /// first line is not a header, and with [`JournalError::VersionTooNew`] on a
    /// journal this build cannot promise to read.
    pub fn open(mut inner: R) -> Result<Self, JournalError> {
        let mut first = String::new();
        let read = inner.read_line(&mut first)?;

        if read == 0 {
            return Err(JournalError::NotAJournal);
        }

        let header: Header =
            serde_json::from_str(first.trim_end()).map_err(|_| JournalError::NotAJournal)?;

        if header.engine != ENGINE_NAME {
            return Err(JournalError::NotAJournal);
        }

        if header.journal_version > JOURNAL_VERSION {
            return Err(JournalError::VersionTooNew {
                found: header.journal_version,
                understood: JOURNAL_VERSION,
            });
        }

        Ok(Self {
            inner,
            line: 1,
            truncated: false,
        })
    }

    /// The 1-based line the reader has most recently consumed. For attaching a
    /// position to an error a caller raises about a record's *contents*, which
    /// this type cannot judge.
    pub fn line(&self) -> u64 {
        self.line
    }

    /// Reads the next record, or `None` at the end of the journal.
    ///
    /// A final line with no trailing newline that does not parse is treated as
    /// the end rather than as an error: it is the torn tail of a process that
    /// died mid-append. A line that does not parse but *is* newline-terminated
    /// was written whole and is corruption, so it is reported.
    pub fn read<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>, JournalError> {
        loop {
            if self.truncated {
                return Ok(None);
            }

            let mut buffer = String::new();
            if self.inner.read_line(&mut buffer)? == 0 {
                return Ok(None);
            }

            self.line += 1;
            let complete = buffer.ends_with('\n');
            self.truncated = !complete;

            let text = buffer.trim_end();
            // A blank line is not a record and not corruption. Skipping it costs
            // nothing and makes a journal survive being concatenated.
            if text.is_empty() {
                continue;
            }

            return match serde_json::from_str(text) {
                Ok(record) => Ok(Some(record)),
                // Torn tail: the writer died between the record and its newline.
                Err(_) if !complete => Ok(None),
                Err(error) => Err(JournalError::Malformed {
                    line: self.line,
                    message: error.to_string(),
                }),
            };
        }
    }
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    struct Sample {
        name: String,
        count: u32,
    }

    fn sample(name: &str) -> Sample {
        Sample {
            name: name.to_string(),
            count: 7,
        }
    }

    fn journal(records: &[Sample]) -> Vec<u8> {
        let mut out = Vec::new();
        let mut writer = Writer::create(&mut out).expect("header");
        for record in records {
            writer.write(record).expect("record");
        }
        out
    }

    /// The point of the whole module: what is written comes back identical.
    #[test]
    fn records_round_trip_through_the_framing() {
        let written = vec![sample("first"), sample("second"), sample("third")];
        let bytes = journal(&written);

        let mut reader = Reader::open(bytes.as_slice()).expect("opens");
        let mut read = Vec::new();
        while let Some(record) = reader.read::<Sample>().expect("reads") {
            read.push(record);
        }

        assert_eq!(read, written);
    }

    /// An empty file is not a journal with no records; it is not a journal.
    #[test]
    fn an_empty_file_is_not_a_journal() {
        assert!(matches!(
            Reader::open(&[][..]),
            Err(JournalError::NotAJournal)
        ));
    }

    /// Somebody else's JSONL must not open as a journal, however well-formed.
    #[test]
    fn a_file_without_a_header_is_refused() {
        let bytes = b"{\"name\":\"first\",\"count\":7}\n";
        assert!(matches!(
            Reader::open(&bytes[..]),
            Err(JournalError::NotAJournal)
        ));
    }

    /// A journal from a future build is refused by name rather than read
    /// approximately: its records may not mean what this build would take them
    /// to mean.
    #[test]
    fn a_newer_journal_version_is_refused() {
        let header = format!(
            "{{\"journal_version\":{},\"engine\":\"{ENGINE_NAME}\",\"engine_version\":\"9.9.9\"}}\n",
            JOURNAL_VERSION + 1
        );

        match Reader::open(header.as_bytes()) {
            Err(JournalError::VersionTooNew { found, understood }) => {
                assert_eq!(found, JOURNAL_VERSION + 1);
                assert_eq!(understood, JOURNAL_VERSION);
            }
            other => panic!("expected a version refusal, got {other:?}"),
        }
    }

    /// The failure this format exists to survive: a process killed mid-append.
    /// Every whole record before the tear must still be readable, and the torn
    /// one must not be an error.
    #[test]
    fn a_torn_final_line_ends_the_journal_without_an_error() {
        let mut bytes = journal(&[sample("first"), sample("second")]);
        bytes.extend_from_slice(b"{\"name\":\"third\",\"cou");

        let mut reader = Reader::open(bytes.as_slice()).expect("opens");
        let mut read = Vec::new();
        while let Some(record) = reader.read::<Sample>().expect("reads past the tear") {
            read.push(record);
        }

        assert_eq!(read, vec![sample("first"), sample("second")]);
    }

    /// A line that was written whole and still does not parse is corruption, not
    /// a tear, and must be reported with where it is rather than silently ending
    /// the journal.
    #[test]
    fn a_complete_line_that_does_not_parse_is_an_error() {
        let mut bytes = journal(&[sample("first")]);
        bytes.extend_from_slice(b"{\"name\":\"second\",\"cou\n");

        let mut reader = Reader::open(bytes.as_slice()).expect("opens");
        assert_eq!(
            reader.read::<Sample>().expect("first"),
            Some(sample("first"))
        );

        match reader.read::<Sample>() {
            Err(JournalError::Malformed { line, .. }) => assert_eq!(line, 3),
            other => panic!("expected a malformed line, got {other:?}"),
        }
    }

    /// A journal from a newer build carrying fields this one does not know stays
    /// readable for what the two have in common.
    #[test]
    fn unknown_fields_are_ignored() {
        let mut bytes = journal(&[]);
        bytes.extend_from_slice(b"{\"name\":\"first\",\"count\":7,\"arrived\":\"later\"}\n");

        let mut reader = Reader::open(bytes.as_slice()).expect("opens");
        assert_eq!(
            reader.read::<Sample>().expect("reads"),
            Some(sample("first"))
        );
    }
}
