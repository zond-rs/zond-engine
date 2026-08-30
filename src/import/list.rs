// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Target Lists
//!
//! A file of targets, one per line, `#` starting a comment. It is what `-iL`
//! reads in every other tool in this space, what a person types, and what falls
//! out of every pipeline anybody has ever built around a scanner.
//!
//! ```text
//! # staging, 2026-02
//! 192.168.1.1
//! 10.0.0.0/24:1-1024
//! [2001:db8::1]:443    # the load balancer
//! db.internal:5432
//! ```
//!
//! ## What separates two targets
//!
//! Newlines and runs of whitespace. **Not commas** - a comma belongs to the
//! expression it is inside, where it separates ports in `10.0.0.1:80,443` and
//! addresses in `10.0.0.1,10.0.0.2`, and only
//! [`TargetExpr`](crate::model::parse::target::TargetExpr) knows which half it landed in.
//! Splitting on commas out here would take the first of those apart into a host
//! and a stray `443`.
//!
//! ## What it tolerates
//!
//! A target list is written by hand, pasted out of a ticket, or produced by
//! something that was itself written by hand, so it is read forgivingly in every
//! way that cannot change which hosts get scanned:
//!
//! - A UTF-8 byte-order mark at the start, which is what a Windows editor
//!   leaves behind and what would otherwise make the first address unparseable.
//! - Both line endings, `\n` and `\r\n`.
//! - Blank lines, and lines that are nothing but a comment.
//! - Any amount of surrounding whitespace.
//!
//! What it does not tolerate is anything that would silently change the scan:
//! bytes that are not UTF-8 and lines longer than the limit are errors naming
//! the line, never a lossy conversion or a truncation.

use std::io::BufRead;

use crate::format::UTF8_BOM_CHAR;
use crate::import::{ImportError, ImportLimits, ImportOrigin, Importer, TargetSink};

/// The character that starts a comment, to the end of its line.
///
/// Only `#`. It is the convention every target list already follows, and no
/// address, range, port specification or hostname can contain one, so nothing a
/// user might legitimately write is at risk of being read as a comment.
const COMMENT: char = '#';

/// Reads a list of target expressions.
///
/// Holds one line at a time, so a file of any size costs the same memory.
#[derive(Debug, Clone, Copy)]
pub struct ListImporter {
    limits: ImportLimits,
}

impl ListImporter {
    /// A reader bounded by `limits`.
    pub fn new(limits: ImportLimits) -> Self {
        Self { limits }
    }
}

impl Default for ListImporter {
    fn default() -> Self {
        Self::new(ImportLimits::default())
    }
}

impl Importer for ListImporter {
    fn import(
        &self,
        input: &mut dyn BufRead,
        sink: &mut dyn TargetSink,
    ) -> Result<(), ImportError> {
        let mut buffer = Vec::new();
        let mut line_number = 0u64;
        let mut first_line = true;

        loop {
            buffer.clear();
            line_number += 1;
            let origin = ImportOrigin::line(line_number);

            if !read_line(input, &mut buffer, self.limits.max_line_bytes, origin)? {
                return Ok(());
            }

            let text =
                std::str::from_utf8(&buffer).map_err(|_| ImportError::InvalidUtf8 { origin })?;

            // Only the first line can carry one, and stripping it anywhere else
            // would silently accept a file that is not what it claims to be.
            let text = if first_line {
                first_line = false;
                text.strip_prefix(UTF8_BOM_CHAR).unwrap_or(text)
            } else {
                text
            };

            let content = match text.split_once(COMMENT) {
                Some((before, _)) => before,
                None => text,
            };

            for token in content.split_whitespace() {
                sink.accept(token, origin)?;
            }
        }
    }
}

/// Reads one line into `buffer`, without its terminator.
///
/// Returns `false` at end of input. The read is bounded before it happens rather
/// than measured after: a file containing no newline at all must not be read
/// into memory to discover that it is too long.
///
/// Shared with the record-per-line formats, which need exactly this bound and
/// exactly these line endings.
pub(crate) fn read_line(
    input: &mut dyn BufRead,
    buffer: &mut Vec<u8>,
    max_line_bytes: usize,
    origin: ImportOrigin,
) -> Result<bool, ImportError> {
    // Two bytes past the limit, which is the longest terminator there is. A
    // line at exactly the limit has to be readable whole however it ends, and
    // budgeting only one byte would refuse a CRLF line for the length of its own
    // line ending.
    let ceiling = (max_line_bytes as u64).saturating_add(2);
    // Spelled out rather than written as a method call: `take` needs a sized
    // receiver, and the reader arrives here as a trait object.
    let mut bounded = std::io::Read::take(&mut *input, ceiling);
    let read = bounded.read_until(b'\n', buffer)?;

    if read == 0 {
        return Ok(false);
    }

    if buffer.last() == Some(&b'\n') {
        buffer.pop();
        if buffer.last() == Some(&b'\r') {
            buffer.pop();
        }
    } else if read as u64 == ceiling {
        // No terminator, and the read stopped at the ceiling: the line runs on
        // past anything that will be accepted. Anything shorter simply reached
        // the end of the input, and a final line with no terminator is ordinary.
        return Err(ImportError::LineTooLong {
            origin,
            limit: max_line_bytes,
        });
    }

    // Checked on the content rather than on the bytes read, so the limit means
    // the same thing whether a line ends with LF, with CRLF, or with the end of
    // the input.
    if buffer.len() > max_line_bytes {
        return Err(ImportError::LineTooLong {
            origin,
            limit: max_line_bytes,
        });
    }

    Ok(true)
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
    use crate::import::{ImportFormat, ImportOptions, Imported};
    use crate::model::port::PortSet;
    use std::io::Cursor;

    fn read(input: &str) -> Imported {
        read_with(input, &ImportOptions::new(PortSet::try_from("80").unwrap()))
    }

    fn read_with(input: &str, options: &ImportOptions<'_>) -> Imported {
        ImportFormat::List
            .read(&mut Cursor::new(input), options)
            .expect("the list imports")
    }

    /// Everything a hand-written list can carry that is not a target, in one
    /// file. None of it may change which hosts get scanned.
    #[test]
    fn the_shapes_a_hand_written_list_arrives_in_are_all_read_the_same() {
        let file = concat!(
            "\u{feff}# staging, 2026-02\r\n",
            "\r\n",
            "   192.168.1.1   \r\n",
            "10.0.0.1 10.0.0.2\t10.0.0.3\n",
            "   # a whole line of comment\n",
            "10.0.0.4   # and a trailing one\n",
            "\n",
            "10.0.0.5",
        );

        let imported = read(file);

        assert_eq!(imported.tokens, 6);
        assert_eq!(imported.addresses, 6);
    }

    /// The byte-order mark is the one that would fail silently and confusingly:
    /// without stripping it, the first address of a file saved by a Windows
    /// editor is refused and every other line works.
    #[test]
    fn a_byte_order_mark_does_not_cost_the_first_target() {
        assert_eq!(read("\u{feff}10.0.0.1\n10.0.0.2\n").addresses, 2);
    }

    /// A comma is never a separator out here. Splitting on it would take
    /// `10.0.0.1:80,443` apart into a host and a stray `443`.
    #[test]
    fn a_comma_stays_inside_the_expression_it_was_written_in() {
        let imported = read("10.0.0.1:80,443\n10.0.0.2,10.0.0.3:22\n");

        assert_eq!(imported.tokens, 2);
        assert_eq!(imported.addresses, 3);
        assert_eq!(imported.map.units.len(), 2, "80 with 443, and 22");
    }

    /// A final line with no newline is ordinary input - a file edited by
    /// something that does not add one, or a here-string - and losing it would
    /// drop a target with nothing to show for it.
    #[test]
    fn a_last_line_without_a_terminator_is_still_a_target() {
        assert_eq!(read("10.0.0.1\n10.0.0.2").addresses, 2);
        assert_eq!(read("10.0.0.1").addresses, 1);
    }

    #[test]
    fn an_empty_input_produces_no_targets_rather_than_an_error() {
        let imported = read("");
        assert_eq!(imported.tokens, 0);
        assert!(imported.map.is_empty());

        assert_eq!(read("\n\n   \n# only a comment\n").tokens, 0);
    }

    /// The bound has to hold before the allocation, not after it: a file with no
    /// newline in it is otherwise read into memory in full to discover that it
    /// was never a target list.
    #[test]
    fn a_line_past_the_limit_is_refused_without_being_read_whole() {
        let options =
            ImportOptions::new(PortSet::try_from("80").unwrap()).with_limits(ImportLimits {
                max_line_bytes: 32,
                ..ImportLimits::default()
            });

        let long = "10.0.0.1 ".repeat(1024);
        let err = ImportFormat::List
            .read(&mut Cursor::new(long), &options)
            .expect_err("a line of nine thousand bytes is not a target list");

        assert!(matches!(err, ImportError::LineTooLong { limit: 32, .. }));
    }

    /// The limit has to mean the same length whichever way a line ends, or a
    /// file saved on Windows is refused for the size of its own line endings.
    #[test]
    fn the_line_limit_counts_content_and_not_the_terminator() {
        let options =
            ImportOptions::new(PortSet::try_from("80").unwrap()).with_limits(ImportLimits {
                max_line_bytes: 8,
                ..ImportLimits::default()
            });

        // Eight bytes of content, in all three ways a line can end.
        for file in ["10.0.0.1\r\n", "10.0.0.1\n", "10.0.0.1"] {
            assert_eq!(read_with(file, &options).addresses, 1, "{file:?}");
        }

        // Nine bytes of content is over the limit, in all three.
        for file in ["10.0.0.12\r\n", "10.0.0.12\n", "10.0.0.12"] {
            let err = ImportFormat::List
                .read(&mut Cursor::new(file), &options)
                .expect_err("nine bytes is past an eight byte limit");
            assert!(
                matches!(err, ImportError::LineTooLong { limit: 8, .. }),
                "{file:?} gave {err:?}"
            );
        }
    }

    /// Bytes that are not UTF-8 are an error naming the line rather than a lossy
    /// conversion, because the replacement character would turn a corrupted
    /// address into something that parses as a hostname.
    #[test]
    fn invalid_utf8_is_refused_rather_than_replaced() {
        let mut input = Cursor::new(b"10.0.0.1\n10.0.0.\xff\xfe2\n".to_vec());
        let options = ImportOptions::new(PortSet::try_from("80").unwrap());

        let err = ImportFormat::List
            .read(&mut input, &options)
            .expect_err("the second line is not text");

        assert!(matches!(
            err,
            ImportError::InvalidUtf8 {
                origin: ImportOrigin { line: Some(2), .. }
            }
        ));
    }

    /// A comment cannot hide a target and a target cannot hide in a comment.
    #[test]
    fn a_comment_runs_to_the_end_of_its_line_and_no_further() {
        let imported = read("10.0.0.1 # 10.0.0.99 10.0.0.98\n10.0.0.2\n");

        assert_eq!(imported.tokens, 2);
        assert_eq!(imported.addresses, 2);
    }
}
