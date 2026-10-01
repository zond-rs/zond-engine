// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The journal's on-disk format
//!
//! One JSON record per line, the first of which describes the file: the framing, the
//! versioning rules, and the vocabulary shared with the export path.
//!
//! ## Why this format is promised and the export DTOs are not
//!
//! [`export::schema`](crate::export::schema) is write-only: it borrows every field and
//! names every enum with a `&'static str`, so the export path allocates nothing per port,
//! and `import::json` reads back only the four fields a rescan needs. A journal has to
//! reconstruct what the first sitting found in full, or the merged report loses it, so this
//! side owns its data, reads what it wrote, and carries a version.
//!
//! ## Compatibility rules (the export document's)
//!
//! - **Unknown fields are ignored.** A journal from a newer build stays readable for what
//!   it has in common with this one.
//! - **An unknown enum string reads downward.** It is one field of one host in a file that
//!   may hold hours of scanning, so it is read as the weakest value the type has: a port
//!   state as `Unasked`, a sitting as a discovery sweep, a severity as `Info`.
//!   [`record`](crate::record) makes that choice field by field and documents each; the
//!   parsers return [`None`].
//! - **[`JOURNAL_VERSION`] is required and checked.** A journal from a newer version is
//!   refused, since its positions may not mean what this build thinks.
//! - **A torn final line is discarded.** The writer appends without an fsync per record
//!   (see [`journal`](super)), so a process killed mid-append leaves a partial last line.
//!   That record falls inside the replay interval anyway.
//!
//! ## Versioned apart from the export schema
//!
//! [`SCHEMA_VERSION`](crate::format::SCHEMA_VERSION) versions the report document and this
//! versions the journal, so an additive change to an export field does not invalidate every
//! scan in flight on disk.
//!
//! ## One vocabulary
//!
//! The wire names are [`record::wire`](crate::record::wire)'s in both directions, so a port
//! state is spelled the same in a report and in a journal.

use std::io::{BufRead, Write};

use serde::{Deserialize, Serialize};

use crate::format::ENGINE_NAME;

#[doc(inline)]
pub use super::JOURNAL_VERSION;

/// What went wrong reading a journal.
#[non_exhaustive]
#[derive(Debug, thiserror::Error)]
pub enum JournalError {
    /// The file did not begin with a header record: it is empty or not a journal this
    /// engine wrote.
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

/// The most one journal file, or one record inside it, may be read into memory.
///
/// Journal files are read out of a directory that belongs to a user (see
/// [`file`](super::file)), often by a root process, so a planted file must not make that
/// process allocate without limit. The import side applies the same standard.
///
/// 256 MiB is far past anything a journal holds. The largest record is one host with every
/// port on both transports and the service detail behind each.
pub(super) const MAX_READ_BYTES: u64 = 256 * 1024 * 1024;

/// What a journal file being past [`MAX_READ_BYTES`] is reported as.
pub(super) fn too_large(what: &str) -> JournalError {
    JournalError::Malformed {
        line: 0,
        message: format!(
            "{what} is larger than the {MAX_READ_BYTES} bytes a journal is read in; \
             this is not a file this engine wrote"
        ),
    }
}

/// The first line of every journal file, so a file read on its own says what it
/// is without a manifest beside it.
///
/// `engine` is recorded as well as the version because a journal may be found in a
/// state directory months later, and should name what produced it.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Header {
    /// The format version, checked against [`JOURNAL_VERSION`] on open.
    pub journal_version: u32,
    /// Always [`ENGINE_NAME`].
    pub engine: String,
    /// The engine build that opened this journal, for diagnostics. A resume is gated by
    /// the plan hash in the manifest, not by this.
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
/// Does not flush per record beyond what the underlying writer does. Durability is
/// the caller's policy; [`journal`](super) documents which failures it survives.
#[derive(Debug)]
pub struct Writer<W: Write> {
    inner: W,
}

impl<W: Write> Writer<W> {
    /// Begins a journal by writing its header.
    pub fn create(mut inner: W) -> Result<Self, JournalError> {
        writeln!(
            inner,
            "{}",
            serde_json::to_string(&Header::current()).map_err(JournalError::json)?
        )?;
        Ok(Self { inner })
    }

    /// Continues a journal that already carries a header, appending to it.
    ///
    /// No header is written and none is checked; checking would need a seekable file.
    /// The caller must have mended a missing header and a torn tail first, as `store`'s
    /// `open_for_append` does. Appending after a torn tail makes the tear stop being the last
    /// line, the only place [`Reader`] discards it, and appending to a file with no header
    /// writes records nothing will read back.
    pub fn append(inner: W) -> Self {
        Self { inner }
    }

    /// Appends one record.
    ///
    /// The newline is written after the record, so a process killed part way through
    /// leaves a line the reader discards. See [`Reader`].
    pub fn write<T: Serialize>(&mut self, record: &T) -> Result<(), JournalError> {
        writeln!(
            self.inner,
            "{}",
            serde_json::to_string(record).map_err(JournalError::json)?
        )?;
        Ok(())
    }

    /// Flushes the underlying writer.
    pub fn flush(&mut self) -> Result<(), JournalError> {
        self.inner.flush()?;
        Ok(())
    }
}

impl JournalError {
    /// A record `serde_json` would not write or read, at no line in
    /// particular.
    ///
    /// Not a `From` impl, because that would make `serde_json`'s error type part of
    /// this crate's public API.
    pub(crate) fn json(error: serde_json::Error) -> Self {
        JournalError::Malformed {
            line: 0,
            message: error.to_string(),
        }
    }
}

/// Reads one line, refusing one past [`MAX_READ_BYTES`].
///
/// The ceiling is applied through `take` before the read, so a file with no newline is
/// refused after reading the ceiling, not the whole file.
fn bounded_line<R: BufRead>(
    inner: &mut R,
    buffer: &mut String,
    what: &str,
) -> Result<usize, JournalError> {
    let mut limited = std::io::Read::take(&mut *inner, MAX_READ_BYTES + 1);
    let read = limited.read_line(buffer)?;
    if read as u64 > MAX_READ_BYTES {
        return Err(too_large(what));
    }
    Ok(read)
}

/// Reads a journal written by [`Writer`], validating its header on open.
#[derive(Debug)]
pub struct Reader<R: BufRead> {
    inner: R,
    line: u64,
    /// Set once a line arrived without a trailing newline. Everything after it is a torn
    /// write, so the reader stops there.
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
        let read = bounded_line(&mut inner, &mut first, "a journal header")?;

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

    /// The 1-based line most recently consumed, for a caller attaching a position to
    /// an error about a record's contents.
    pub fn line(&self) -> u64 {
        self.line
    }

    /// Reads the next record, or `None` at the end of the journal.
    ///
    /// A final line with no trailing newline that does not parse is the torn tail of a
    /// process that died mid-append, and ends the journal. A newline-terminated line that does
    /// not parse was written whole and is reported as corruption.
    pub fn read<T: for<'de> Deserialize<'de>>(&mut self) -> Result<Option<T>, JournalError> {
        loop {
            if self.truncated {
                return Ok(None);
            }

            let mut buffer = String::new();
            if bounded_line(&mut self.inner, &mut buffer, "a journal record")? == 0 {
                return Ok(None);
            }

            self.line += 1;
            let complete = buffer.ends_with('\n');
            self.truncated = !complete;

            let text = buffer.trim_end();
            // Skipping blank lines lets a journal survive being concatenated.
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

    /// What is written comes back identical.
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

    /// An empty file is not a journal.
    #[test]
    fn an_empty_file_is_not_a_journal() {
        assert!(matches!(
            Reader::open(&[][..]),
            Err(JournalError::NotAJournal)
        ));
    }

    /// Somebody else's JSONL does not open as a journal, however well-formed.
    #[test]
    fn a_file_without_a_header_is_refused() {
        let bytes = b"{\"name\":\"first\",\"count\":7}\n";
        assert!(matches!(
            Reader::open(&bytes[..]),
            Err(JournalError::NotAJournal)
        ));
    }

    /// A journal from a future build is refused by name: its records may not mean what
    /// this build would take them to mean.
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

    /// A process killed mid-append: every whole record before the tear is readable,
    /// and the torn one is not an error.
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

    /// A line written whole that does not parse is corruption, reported with its line
    /// number.
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
