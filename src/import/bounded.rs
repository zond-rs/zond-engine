// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The whole-document byte ceiling
//!
//! Every reader in [`import`](crate::import) takes a document through
//! [`within`], the target readers under
//! [`ImportLimits::max_document_bytes`](crate::import::ImportLimits::max_document_bytes)
//! and the report readers under
//! [`ReportOptions::max_document_bytes`](crate::import::report::ReportOptions::max_document_bytes).
//! The ceiling is enforced on the stream rather than by each format's parser,
//! so it holds the same way for every format and a format added later has
//! only to be read through here.

use std::io::BufRead;

use crate::import::ImportError;

/// Runs `read` over `input` cut off after `limit` bytes, and names the
/// refusal [`ImportError::DocumentTooLarge`] if that is why it failed.
///
/// A document of exactly `limit` bytes is read whole.
pub(crate) fn within<T>(
    input: &mut dyn BufRead,
    limit: u64,
    read: impl FnOnce(&mut dyn BufRead) -> Result<T, ImportError>,
) -> Result<T, ImportError> {
    let mut bounded = Bounded::new(input, limit);
    match read(&mut bounded) {
        Err(_) if bounded.exhausted => Err(ImportError::DocumentTooLarge { limit }),
        other => other,
    }
}

/// A reader that refuses to hand out more than `limit` bytes.
struct Bounded<'a> {
    inner: &'a mut dyn BufRead,
    left: u64,
    /// Whether the budget ran out, which is all [`within`] needs back. A flag
    /// rather than a distinguishable error: the refusal travels out through
    /// `serde_json` and through the XML parser, and both rewrite an I/O
    /// failure into an error of their own. Asking afterwards is exact where
    /// reading the message that came back would be a guess.
    exhausted: bool,
}

impl<'a> Bounded<'a> {
    fn new(inner: &'a mut dyn BufRead, limit: u64) -> Self {
        Self {
            inner,
            left: limit,
            exhausted: false,
        }
    }

    fn over_budget(&mut self) -> std::io::Error {
        self.exhausted = true;
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the document is past its byte ceiling",
        )
    }
}

impl Bounded<'_> {
    /// Whether a reader asking for more bytes is asking for more than the
    /// budget, rather than asking how it ends.
    ///
    /// A spent budget is not by itself an overrun. A document of exactly
    /// `max_document_bytes` has been handed over whole, and a parser then asks
    /// once more because that is how it learns there is nothing after the value
    /// it read. Refusing that reading would make the ceiling refuse the largest
    /// document it is supposed to admit.
    fn overran(&mut self) -> std::io::Result<bool> {
        Ok(self.left == 0 && !self.inner.fill_buf()?.is_empty())
    }
}

impl std::io::Read for Bounded<'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.overran()? {
            return Err(self.over_budget());
        }
        let ceiling = usize::try_from(self.left).unwrap_or(usize::MAX);
        let take = buf.len().min(ceiling);
        let read = self.inner.read(&mut buf[..take])?;
        self.left -= read as u64;
        Ok(read)
    }
}

impl BufRead for Bounded<'_> {
    fn fill_buf(&mut self) -> std::io::Result<&[u8]> {
        if self.overran()? {
            return Err(self.over_budget());
        }
        let ceiling = usize::try_from(self.left).unwrap_or(usize::MAX);
        let available = self.inner.fill_buf()?;
        Ok(&available[..available.len().min(ceiling)])
    }

    fn consume(&mut self, amount: usize) {
        self.left = self.left.saturating_sub(amount as u64);
        self.inner.consume(amount);
    }
}
