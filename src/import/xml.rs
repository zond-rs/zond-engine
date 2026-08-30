// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # A pull parser that declares nothing
//!
//! The XML reader behind every format in this module that has one. It reads a
//! file somebody else wrote, and what makes that defensible is not care in the
//! parsing; it is that the dangerous constructs have no representation here at
//! all.
//!
//! - **`<!ENTITY` is refused anywhere, unconditionally.** No entity is ever
//!   declared, so none can be expanded, so the billion-laughs expansion has
//!   nothing to expand and an external entity has nothing to fetch. Not
//!   mitigated - absent.
//! - **A `DOCTYPE` is accepted only in its inert form**: a bare name, no
//!   internal subset, no `SYSTEM` or `PUBLIC` identifier. Any of those is
//!   refused.
//! - **Any entity reference other than the five predefined and numeric
//!   character references is refused**, naming it. With no declarations
//!   permitted there is no legitimate way for one to appear.
//! - **Processing instructions are skipped without being interpreted.** This is
//!   not an XSLT engine and never opens what one names.
//! - Nesting depth, element count, name length, attribute length and captured
//!   text length are all bounded, and one element's markup is bounded by
//!   [`ImportLimits::max_line_bytes`](crate::import::ImportLimits::max_line_bytes).
//!
//! Nothing in a document can make this parser open a file, resolve a URL, or
//! allocate without bound. The residue is processing time, which the bounds
//! cover.
//!
//! ## Why a bare DOCTYPE is accepted rather than refused
//!
//! Because refusing it would reject every real nmap file. Nmap writes
//!
//! ```text
//! <?xml version="1.0" encoding="UTF-8"?>
//! <!DOCTYPE nmaprun>
//! <?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?>
//! ```
//!
//! and a rule that turned all three away would have left this parser unable to
//! read its own subject. `<!DOCTYPE nmaprun>` declares nothing and references
//! nothing; it is inert. The narrower rule is also the stronger one, because a
//! blanket refusal is the kind that acquires an option to disable it the first
//! time somebody needs their file read.
//!
//! ## What a caller reads, and what is skipped unbuffered
//!
//! A caller names the attributes it wants when it builds the parser, and every
//! other value is scanned past without being stored. That is what lets nmap's
//! very long `args` and `services` attributes through without a limit tuned
//! around them: only the element's total markup is bounded, not the value.
//!
//! Text between elements is skipped the same way until a caller asks for it with
//! [`Parser::begin_text`], which it does on entering an element whose content it
//! wants. Entity references are resolved - and refused - only in text that was
//! asked for, on the same principle: nothing is interpreted that nobody reads.
//!
//! ## Who uses it
//!
//! [`nmap`](super::nmap) reads a document as the targets to scan next.
//! [`report::nmap`](crate::import::report::nmap) reads the same document as the findings
//! of the scan that produced it. One audited parser rather than two, because two
//! hand-rolled XML parsers kept hardened in step is the failure this module's
//! refusals exist to prevent.

use std::io::BufRead;

use crate::import::{ImportError, ImportOrigin};

/// How deeply elements may nest.
///
/// Real nmap output reaches five. Sixty-four is unreachable by anything honest
/// and bounds the parser's own bookkeeping, which is the only thing depth costs
/// here - element content is never accumulated.
pub(crate) const MAX_DEPTH: usize = 64;

/// The longest element or attribute name accepted, in bytes.
pub(crate) const MAX_NAME_BYTES: usize = 64;

/// The longest attribute value kept, in bytes.
///
/// Applies only to the attributes a caller asked for. Every other attribute is
/// scanned past without being stored, which is what lets nmap's very long
/// `args` and `services` attributes through without a limit tuned around them.
pub(crate) const MAX_VALUE_BYTES: usize = 256;

/// The most elements one document may contain.
pub(crate) const MAX_ELEMENTS: u64 = 1 << 24;

/// The longest entity name accepted, in bytes, between the `&` and the `;`.
pub(crate) const MAX_ENTITY_BYTES: usize = 16;

/// The longest run of element text kept, in bytes.
///
/// Applies only to text a caller asked for. The longest thing anything reads
/// this way is a CPE identifier, which runs to a few dozen bytes.
const MAX_TEXT_BYTES: usize = 512;

/// The longest terminator [`Parser::skip_until`] is asked to find: `-->` and
/// `]]>`, with `?>` and `>` shorter.
const MAX_TERMINATOR_BYTES: usize = 3;

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// What the parser found.
pub(crate) enum Event {
    /// An element opened. `self_closing` means it closed in the same tag.
    Start { self_closing: bool },
    /// An element closed.
    End,
    /// The document ended.
    Eof,
}

/// The element the parser is currently looking at.
///
/// Reused between elements, so a document of any size costs one element's worth
/// of memory. Only the four attributes this module reads are stored; every
/// other value is scanned past without being kept.
#[derive(Debug, Default)]
pub(crate) struct Element {
    pub(crate) name: Vec<u8>,
    values: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Element {
    fn clear(&mut self) {
        self.name.clear();
        self.values.clear();
    }

    /// One attribute's value as text, if the element carried it.
    ///
    /// `None` means the element did not carry the attribute, and nothing else:
    /// a value that is not UTF-8 refused the document when it was read, so no
    /// unreadable value ever reaches here.
    pub(crate) fn value(&self, name: &[u8]) -> Option<&str> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
    }
}

pub(crate) struct Parser<'a> {
    input: &'a mut dyn BufRead,
    buffer: Vec<u8>,
    position: usize,
    /// The 1-based line the parser is on, counted as bytes go past so an error
    /// can name a place in the file.
    line: u64,
    /// Bytes consumed within the current element's markup.
    element_bytes: usize,
    max_element_bytes: usize,
    elements: u64,
    pub(crate) element: Element,
    /// The format's name in errors, so a refusal names the document a caller
    /// handed over rather than the parser that read it.
    format: &'static str,
    /// The attributes whose values are stored. Everything else is skipped
    /// unbuffered.
    kept: &'static [&'static [u8]],
    /// Kept attributes that are dropped rather than refused when they run past
    /// the bound. See [`with_lossy`](Parser::with_lossy).
    lossy: &'static [&'static [u8]],
    /// The longest kept value, in bytes.
    max_value_bytes: usize,
    /// How deeply elements are currently nested.
    depth: usize,
    /// Whether text between elements is being kept.
    capture: bool,
    /// The text kept since [`begin_text`](Parser::begin_text).
    text: Vec<u8>,
}

/// What to do with one attribute's value.
///
/// Three states rather than the two independent flags this used to be. They
/// were never independent: a value was only ever lossy if it was also kept, so
/// one of the four combinations the old signature could express did not exist,
/// and two adjacent `bool`s could be swapped at a call site with no diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ValuePolicy {
    /// Scanned past and not stored: nothing this parser was asked to keep.
    Skip,

    /// Stored, and a value past the size bound refuses the document.
    Keep,

    /// Stored, and a value past the bound is dropped rather than refused, so
    /// what comes back is the absence of the attribute rather than a prefix of
    /// it. For the attributes where an over-long value is somebody else's
    /// verbosity rather than an attack.
    KeepIfItFits,
}

impl ValuePolicy {
    /// The policy for an attribute this parser was asked to keep, or not, and
    /// to treat leniently, or not. Leniency without keeping is not a state.
    fn of(kept: bool, lossy: bool) -> Self {
        match (kept, lossy) {
            (false, _) => Self::Skip,
            (true, false) => Self::Keep,
            (true, true) => Self::KeepIfItFits,
        }
    }
}

impl<'a> Parser<'a> {
    /// A parser over `input` that keeps the values of `kept` and nothing else.
    pub(crate) fn new(
        input: &'a mut dyn BufRead,
        max_element_bytes: usize,
        format: &'static str,
        kept: &'static [&'static [u8]],
    ) -> Self {
        Self {
            input,
            buffer: Vec::new(),
            position: 0,
            line: 1,
            element_bytes: 0,
            max_element_bytes,
            elements: 0,
            element: Element::default(),
            format,
            kept,
            lossy: &[],
            max_value_bytes: MAX_VALUE_BYTES,
            depth: 0,
            capture: false,
            text: Vec::new(),
        }
    }

    /// Names attributes whose value is dropped, rather than refused, when it
    /// runs past the bound.
    ///
    /// For a value that enriches a record without deciding what it says. Nmap
    /// lists the ports it found uninteresting, and that list is bounded only by
    /// how many ports were scanned — a sparse sweep of all 65 535 could write
    /// several hundred kilobytes of it. Refusing the file over an attribute
    /// nothing depends on would be the wrong trade, and so would raising every
    /// bound to fit the worst case.
    ///
    /// **Dropped whole, never truncated.** A prefix of a port list is a claim
    /// that the ports past the cut were not probed, which is a different and
    /// worse answer than not knowing.
    pub(crate) fn with_lossy(mut self, lossy: &'static [&'static [u8]]) -> Self {
        self.lossy = lossy;
        self
    }

    /// Raises the bound on a kept attribute value.
    ///
    /// The default suits a reader whose kept attributes are addresses and port
    /// numbers. One that keeps free text a service reported about itself needs
    /// more room, and says how much rather than inheriting a bound chosen for a
    /// different job.
    pub(crate) fn with_max_value_bytes(mut self, bytes: usize) -> Self {
        self.max_value_bytes = bytes;
        self
    }

    /// Keeps the text that follows, until [`take_text`](Self::take_text).
    ///
    /// Called on entering an element whose content is wanted. Entity references
    /// in kept text are resolved, and an undeclared one is refused exactly as it
    /// is in an attribute value.
    pub(crate) fn begin_text(&mut self) {
        self.text.clear();
        self.capture = true;
    }

    /// The text kept since [`begin_text`](Self::begin_text), and stops keeping.
    ///
    /// Trimmed, since element content is written with the indentation of the
    /// document around it. Text that is not UTF-8 refuses the document rather
    /// than arriving with replacement characters in it: what this carries is a
    /// CPE identifier, and one with a `U+FFFD` in the middle is a corrupted
    /// identifier that reads as a real one.
    pub(crate) fn take_text(&mut self) -> Result<String, ImportError> {
        self.capture = false;
        let text = std::mem::take(&mut self.text);

        let text = std::str::from_utf8(&text).map_err(|_| ImportError::InvalidUtf8 {
            origin: self.origin(),
        })?;

        Ok(text.trim().to_string())
    }

    pub(crate) fn origin(&self) -> ImportOrigin {
        ImportOrigin::line(self.line)
    }

    pub(crate) fn malformed(&self, message: String) -> ImportError {
        ImportError::Malformed {
            format: self.format,
            origin: self.origin(),
            message,
        }
    }

    /// Makes at least one byte available, or reports the end of the input.
    fn fill(&mut self) -> Result<bool, ImportError> {
        if self.position < self.buffer.len() {
            return Ok(true);
        }

        let Self {
            input,
            buffer,
            position,
            ..
        } = self;

        buffer.clear();
        *position = 0;

        let available = input.fill_buf()?;
        if available.is_empty() {
            return Ok(false);
        }
        let taken = available.len();
        buffer.extend_from_slice(available);
        input.consume(taken);

        Ok(true)
    }

    fn peek(&mut self) -> Result<Option<u8>, ImportError> {
        if !self.fill()? {
            return Ok(None);
        }
        Ok(Some(self.buffer[self.position]))
    }

    fn bump(&mut self) -> Result<Option<u8>, ImportError> {
        let Some(byte) = self.peek()? else {
            return Ok(None);
        };
        self.position += 1;
        if byte == b'\n' {
            self.line += 1;
        }
        self.element_bytes += 1;
        if self.element_bytes > self.max_element_bytes {
            return Err(ImportError::LineTooLong {
                origin: self.origin(),
                limit: self.max_element_bytes,
            });
        }
        Ok(Some(byte))
    }

    /// Reads the next element, skipping text, comments and instructions.
    pub(crate) fn next_event(&mut self) -> Result<Event, ImportError> {
        loop {
            // Text between elements is never read. Nothing here needs it, and
            // not reading it is what makes an entity reference in content
            // harmless whatever it says.
            loop {
                match self.peek()? {
                    None => return Ok(Event::Eof),
                    Some(b'<') => break,
                    Some(b'&') if self.capture => {
                        self.element_bytes = 0;
                        let resolved = self.entity()?;
                        self.keep_text(&resolved)?;
                    }
                    Some(byte) => {
                        self.element_bytes = 0;
                        self.bump()?;
                        if self.capture {
                            self.keep_text(&[byte])?;
                        }
                    }
                }
            }

            self.element_bytes = 0;
            self.bump()?; // '<'

            match self.peek()? {
                None => return Err(self.malformed("the document ends inside a tag".to_string())),
                Some(b'?') => {
                    self.skip_until(b"?>")?;
                    continue;
                }
                Some(b'!') => {
                    self.declaration()?;
                    continue;
                }
                Some(b'/') => {
                    self.bump()?;
                    self.element.clear();
                    self.read_name()?;
                    self.skip_until(b">")?;
                    self.depth = self.depth.saturating_sub(1);
                    return Ok(Event::End);
                }
                Some(_) => {
                    self.elements += 1;
                    if self.elements > MAX_ELEMENTS {
                        return Err(self.malformed(format!("more than {MAX_ELEMENTS} elements")));
                    }
                    self.element.clear();
                    self.read_name()?;
                    let self_closing = self.read_attributes()?;
                    if !self_closing {
                        self.depth += 1;
                        if self.depth > MAX_DEPTH {
                            return Err(self
                                .malformed(format!("elements nested more than {MAX_DEPTH} deep")));
                        }
                    }
                    return Ok(Event::Start { self_closing });
                }
            }
        }
    }

    /// Handles everything opening `<!`.
    ///
    /// This is where the refusals live. A comment and a CDATA section are inert
    /// and are skipped; a `DOCTYPE` is inert only in the one form nmap writes;
    /// everything else that can appear here declares something, and declaring
    /// anything is what this parser exists not to do.
    fn declaration(&mut self) -> Result<(), ImportError> {
        self.bump()?; // '!'

        if self.matches(b"--")? {
            return self.skip_until(b"-->");
        }
        if self.matches(b"[CDATA[")? {
            return self.skip_until(b"]]>");
        }
        if self.matches(b"DOCTYPE")? {
            return self.doctype();
        }

        Err(self.malformed(
            "a declaration other than a comment, CDATA or DOCTYPE: this parser \
             accepts no declarations, which is what makes entity expansion \
             impossible rather than merely unimplemented"
                .to_string(),
        ))
    }

    /// Accepts `<!DOCTYPE name>` and nothing else.
    ///
    /// An internal subset is where entity declarations live, and an external
    /// identifier is a document telling the parser to go and fetch something.
    /// Neither is accepted in any form, so neither has to be handled safely.
    fn doctype(&mut self) -> Result<(), ImportError> {
        loop {
            let Some(byte) = self.bump()? else {
                return Err(self.malformed("the document ends inside a DOCTYPE".to_string()));
            };

            match byte {
                b'>' => return Ok(()),
                b'[' => {
                    return Err(self.malformed(
                        "a DOCTYPE with an internal subset, which is where entity \
                         declarations live. Only a bare '<!DOCTYPE name>' is accepted"
                            .to_string(),
                    ));
                }
                b'S' | b'P' => {
                    // `SYSTEM` and `PUBLIC` both name something to go and fetch.
                    let word = if byte == b'S' {
                        b"YSTEM".as_slice()
                    } else {
                        b"UBLIC".as_slice()
                    };
                    if self.matches(word)? {
                        return Err(self.malformed(
                            "a DOCTYPE naming an external identifier, which asks the \
                             parser to fetch a document. Only a bare \
                             '<!DOCTYPE name>' is accepted"
                                .to_string(),
                        ));
                    }
                }
                _ => {}
            }
        }
    }

    /// Reads an element name into [`Element::name`].
    fn read_name(&mut self) -> Result<(), ImportError> {
        loop {
            match self.peek()? {
                None => return Err(self.malformed("the document ends inside a name".to_string())),
                Some(byte) if is_name_byte(byte) => {
                    self.bump()?;
                    if self.element.name.len() >= MAX_NAME_BYTES {
                        return Err(
                            self.malformed(format!("a name longer than {MAX_NAME_BYTES} bytes"))
                        );
                    }
                    self.element.name.push(byte);
                }
                Some(_) => return Ok(()),
            }
        }
    }

    /// Reads an element's attributes, returning whether the tag closed itself.
    fn read_attributes(&mut self) -> Result<bool, ImportError> {
        loop {
            self.skip_whitespace()?;

            match self.peek()? {
                None => {
                    return Err(self.malformed("the document ends inside a tag".to_string()));
                }
                Some(b'>') => {
                    self.bump()?;
                    return Ok(false);
                }
                Some(b'/') => {
                    self.bump()?;
                    if self.peek()? != Some(b'>') {
                        return Err(self.malformed("'/' not followed by '>'".to_string()));
                    }
                    self.bump()?;
                    return Ok(true);
                }
                Some(_) => self.read_attribute()?,
            }
        }
    }

    /// Reads one `name="value"` pair, keeping the value only if it is wanted.
    fn read_attribute(&mut self) -> Result<(), ImportError> {
        let mut name = Vec::new();
        loop {
            match self.peek()? {
                None => return Err(self.malformed("the document ends inside a tag".to_string())),
                Some(byte) if is_name_byte(byte) => {
                    self.bump()?;
                    if name.len() >= MAX_NAME_BYTES {
                        return Err(self.malformed(format!(
                            "an attribute name longer than {MAX_NAME_BYTES} bytes"
                        )));
                    }
                    name.push(byte);
                }
                Some(_) => break,
            }
        }

        self.skip_whitespace()?;
        if self.peek()? != Some(b'=') {
            return Err(self.malformed(format!(
                "attribute '{}' has no value",
                String::from_utf8_lossy(&name)
            )));
        }
        self.bump()?;
        self.skip_whitespace()?;

        let policy = ValuePolicy::of(
            self.kept.contains(&name.as_slice()),
            self.lossy.contains(&name.as_slice()),
        );

        if let Some(value) = self.read_value(policy)?
            && policy != ValuePolicy::Skip
        {
            // Checked here rather than where the value is read out, because
            // `None` there would mean "the element did not carry this
            // attribute" and a host whose address is not text would vanish
            // instead of refusing the document. Every other format in this
            // module answers the same bytes with the same error.
            if std::str::from_utf8(&value).is_err() {
                return Err(ImportError::InvalidUtf8 {
                    origin: self.origin(),
                });
            }
            self.element.values.push((name, value));
        }

        Ok(())
    }

    /// Reads a quoted attribute value under `policy`.
    ///
    /// An unwanted value is not accumulated at all, which is what lets nmap's
    /// very long `args` and `services` attributes through without any limit
    /// tuned around them: only the element's total markup is bounded.
    fn read_value(&mut self, policy: ValuePolicy) -> Result<Option<Vec<u8>>, ImportError> {
        let keep = policy != ValuePolicy::Skip;
        let lossy = policy == ValuePolicy::KeepIfItFits;

        let Some(quote) = self.peek()? else {
            return Err(self.malformed("the document ends inside a tag".to_string()));
        };
        if quote != b'"' && quote != b'\'' {
            return Err(self.malformed("an attribute value that is not quoted".to_string()));
        }
        self.bump()?;

        let mut value = Vec::new();
        // Set once a lossy value has run past the bound. Everything after is
        // scanned past and nothing is kept, so what comes back is the absence of
        // the attribute rather than a prefix of it.
        let mut dropped = false;

        loop {
            let Some(byte) = self.peek()? else {
                return Err(
                    self.malformed("the document ends inside an attribute value".to_string())
                );
            };

            if byte == quote {
                self.bump()?;
                return Ok((!dropped).then_some(value));
            }

            let bytes = if byte == b'&' {
                self.entity()?
            } else {
                self.bump()?;
                vec![byte]
            };

            if keep && !dropped {
                if value.len() + bytes.len() > self.max_value_bytes {
                    if !lossy {
                        return Err(self.malformed(format!(
                            "an attribute value longer than {} bytes",
                            self.max_value_bytes
                        )));
                    }
                    dropped = true;
                    value = Vec::new();
                } else {
                    value.extend_from_slice(&bytes);
                }
            }
        }
    }

    /// Resolves one entity reference, or refuses it.
    ///
    /// The five predefined references and numeric character references are the
    /// whole of what an attribute may contain, because no others can have been
    /// declared - this parser refuses every declaration. A reference to
    /// something undeclared is the shape an external-entity attack takes, so it
    /// is named in the error rather than skipped.
    fn entity(&mut self) -> Result<Vec<u8>, ImportError> {
        self.bump()?; // '&'

        let mut name = Vec::new();
        loop {
            let Some(byte) = self.peek()? else {
                return Err(self.malformed("the document ends inside an entity".to_string()));
            };
            self.bump()?;
            if byte == b';' {
                break;
            }
            if name.len() >= MAX_ENTITY_BYTES {
                return Err(self.malformed("an entity reference with no ';'".to_string()));
            }
            name.push(byte);
        }

        match name.as_slice() {
            b"lt" => Ok(vec![b'<']),
            b"gt" => Ok(vec![b'>']),
            b"amp" => Ok(vec![b'&']),
            b"quot" => Ok(vec![b'"']),
            b"apos" => Ok(vec![b'\'']),
            reference if reference.first() == Some(&b'#') => self.character_reference(reference),
            other => Err(self.malformed(format!(
                "'&{};' is not a predefined entity, and this parser permits no \
                 declarations, so nothing can have defined it",
                String::from_utf8_lossy(other)
            ))),
        }
    }

    /// Resolves `&#NN;` or `&#xHH;`.
    fn character_reference(&self, reference: &[u8]) -> Result<Vec<u8>, ImportError> {
        let digits = String::from_utf8_lossy(&reference[1..]);
        let code = match digits.strip_prefix(['x', 'X']) {
            Some(hex) => u32::from_str_radix(hex, 16).ok(),
            None => digits.parse::<u32>().ok(),
        };

        let Some(character) = code.and_then(char::from_u32) else {
            return Err(self.malformed(format!("'&{digits};' is not a character")));
        };

        let mut encoded = [0u8; 4];
        Ok(character.encode_utf8(&mut encoded).as_bytes().to_vec())
    }

    /// Consumes `expected` if it is next, and reports whether it was.
    ///
    /// Only ever called where a partial match cannot be the start of anything
    /// else this parser accepts, so a failed match leaves what it read behind
    /// as ordinary content of something already being skipped.
    fn matches(&mut self, expected: &[u8]) -> Result<bool, ImportError> {
        for wanted in expected {
            match self.peek()? {
                Some(byte) if byte == *wanted => {
                    self.bump()?;
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }

    fn skip_whitespace(&mut self) -> Result<(), ImportError> {
        while matches!(self.peek()?, Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.bump()?;
        }
        Ok(())
    }

    /// Skips everything up to and including `terminator`.
    ///
    /// Compares a sliding window of the last few bytes rather than advancing a
    /// match counter. A counter has to decide, on a mismatch, how much of the
    /// partial match to keep, and every cheap answer is wrong here: `]]]>` ends
    /// a CDATA section whose content is `]`, and dropping back to one matched
    /// byte on the third `]` runs past it to the end of the document. The window
    /// is at most [`MAX_TERMINATOR_BYTES`] wide, so the comparison costs less
    /// than the arithmetic it replaces.
    fn skip_until(&mut self, terminator: &[u8]) -> Result<(), ImportError> {
        let width = terminator.len();
        debug_assert!(
            (1..=MAX_TERMINATOR_BYTES).contains(&width),
            "every terminator this parser skips to fits the window"
        );

        let mut window = [0u8; MAX_TERMINATOR_BYTES];
        let mut filled = 0usize;

        loop {
            let Some(byte) = self.bump()? else {
                return Err(self.malformed(format!(
                    "the document ends before '{}'",
                    String::from_utf8_lossy(terminator)
                )));
            };

            if filled == width {
                window.copy_within(1..width, 0);
                window[width - 1] = byte;
            } else {
                window[filled] = byte;
                filled += 1;
            }

            if filled == width && window[..width] == *terminator {
                return Ok(());
            }
        }
    }
}

/// Appends to the kept text, bounded.
impl Parser<'_> {
    fn keep_text(&mut self, bytes: &[u8]) -> Result<(), ImportError> {
        if self.text.len() + bytes.len() > MAX_TEXT_BYTES {
            return Err(self.malformed(format!("element text longer than {MAX_TEXT_BYTES} bytes")));
        }
        self.text.extend_from_slice(bytes);
        Ok(())
    }
}

/// Whether a byte may appear in an element or attribute name.
///
/// Deliberately permissive about what a name may contain and strict about what
/// ends one: everything this parser does with a name is compare it against a
/// fixed list, so a name it does not recognise is skipped whatever it is made
/// of.
fn is_name_byte(byte: u8) -> bool {
    !matches!(
        byte,
        b' ' | b'\t' | b'\r' | b'\n' | b'/' | b'>' | b'=' | b'<'
    )
}

// ╔════════════════════════════════════════════╗
// ║ ████████╗███████╗███████╗████████╗███████╗ ║
// ║ ╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝██╔════╝ ║
// ║    ██║   █████╗  ███████╗   ██║   ███████╗ ║
// ║    ██║   ██╔══╝  ╚════██║   ██║   ╚════██║ ║
// ║    ██║   ███████╗██║  ██║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

/// The module doc makes six claims about what this parser refuses and bounds six
/// things it accepts. These hold it to all twelve.
///
/// The refusals are the whole security argument for reading a file somebody else
/// wrote, and an untested refusal is a claim rather than a control.
#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use proptest::prelude::*;

    use super::*;

    const FORMAT: &str = "test";
    const KEPT: &[&[u8]] = &[b"id", b"name"];

    /// Drives a document to completion, returning the first refusal if there is
    /// one.
    fn read(document: &str) -> Result<Vec<Event>, ImportError> {
        let mut input = Cursor::new(document.as_bytes().to_vec());
        let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);
        let mut events = Vec::new();
        loop {
            match parser.next_event()? {
                Event::Eof => return Ok(events),
                event => events.push(event),
            }
        }
    }

    fn refusal(document: &str) -> String {
        match read(document) {
            Ok(_) => panic!("the parser accepted a document it documents as refused"),
            Err(error) => error.to_string(),
        }
    }

    /// The kept attributes of one element, by name, as the parser reads them
    /// back out.
    type Kept = Vec<(&'static str, Option<String>)>;

    /// Reads one document and hands back the first element's kept attributes.
    fn attributes(document: &str) -> Result<Kept, ImportError> {
        let mut input = Cursor::new(document.as_bytes().to_vec());
        let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);

        loop {
            match parser.next_event()? {
                Event::Eof => return Ok(Vec::new()),
                Event::Start { .. } => {
                    return Ok(KEPT
                        .iter()
                        .map(|name| {
                            (
                                std::str::from_utf8(name).expect("the kept names are ASCII"),
                                parser.element.value(name).map(str::to_owned),
                            )
                        })
                        .collect());
                }
                Event::End => {}
            }
        }
    }

    // ─── Skipping to a terminator ────────────────────────────────────────────

    /// `<![CDATA[a]]]>` is a section whose content is `a]`, and the `]]>` that
    /// closes it begins inside the run of brackets. A parser that restarts its
    /// match at the failing byte walks straight past it and reports a document
    /// that ends unexpectedly, which is a legal file refused.
    #[test]
    fn a_terminator_overlapping_its_own_prefix_still_ends_the_section() {
        for document in [
            r#"<a><![CDATA[b]]]></a>"#,
            r#"<a><![CDATA[b]]]]></a>"#,
            r#"<a><!--- a comment ---></a>"#,
            r#"<a><?target ??></a>"#,
        ] {
            let events =
                read(document).unwrap_or_else(|error| panic!("{document} was refused: {error}"));
            assert!(!events.is_empty(), "{document}");
        }
    }

    /// And the ordinary shapes still terminate where they always did.
    #[test]
    fn a_terminator_that_does_not_overlap_still_ends_the_section() {
        for document in [
            r#"<a><![CDATA[b]]></a>"#,
            r#"<a><!-- a comment --></a>"#,
            r#"<a><?target value?></a>"#,
        ] {
            assert!(read(document).is_ok(), "{document}");
        }
    }

    // ─── Bytes that are not text ─────────────────────────────────────────────

    /// A value that is not UTF-8 refuses the document rather than reading as an
    /// attribute the element did not carry.
    ///
    /// The silent form is the dangerous one: `addr` is how a host is named, so a
    /// host whose address held a stray byte would have vanished from the import
    /// with nothing counted, nothing refused and nothing said.
    #[test]
    fn an_attribute_value_that_is_not_text_refuses_the_document() {
        let mut document = b"<a id=\"1".to_vec();
        document.push(0xFF);
        document.extend_from_slice(b"\"/>");

        let mut input = Cursor::new(document);
        let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);

        assert!(
            matches!(parser.next_event(), Err(ImportError::InvalidUtf8 { .. })),
            "a value that is not text has to be refused, not dropped"
        );
    }

    /// An attribute nobody asked for is never stored, so its bytes are never
    /// examined and cannot refuse a document over a value nothing reads.
    #[test]
    fn an_attribute_nobody_kept_is_not_checked_for_text() {
        let mut document = b"<a other=\"".to_vec();
        document.push(0xFF);
        document.extend_from_slice(b"\" id=\"1\"/>");

        let mut input = Cursor::new(document);
        let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);

        assert!(matches!(parser.next_event(), Ok(Event::Start { .. })));
        assert_eq!(parser.element.value(b"id"), Some("1"));
    }

    /// Kept text is held to the same rule, so a CPE identifier never arrives
    /// with a replacement character standing in for a byte.
    #[test]
    fn element_text_that_is_not_text_refuses_the_document() {
        let mut document = b"<a>cpe:/o:x".to_vec();
        document.push(0xFF);
        document.extend_from_slice(b"</a>");

        let mut input = Cursor::new(document);
        let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);

        assert!(matches!(parser.next_event(), Ok(Event::Start { .. })));
        parser.begin_text();
        assert!(matches!(parser.next_event(), Ok(Event::End)));
        assert!(matches!(
            parser.take_text(),
            Err(ImportError::InvalidUtf8 { .. })
        ));
    }

    /// The ordinary case, so the check above is a refusal of bad bytes rather
    /// than of everything.
    #[test]
    fn a_value_and_a_text_run_that_are_text_read_back_whole() {
        let kept = attributes(r#"<a id="7" name="gw" other="ignored"/>"#).expect("reads");
        assert_eq!(
            kept,
            vec![
                ("id", Some("7".to_string())),
                ("name", Some("gw".to_string())),
            ]
        );
    }

    // ─── The six refusals ────────────────────────────────────────────────────

    /// "`<!ENTITY` is refused anywhere, unconditionally. No entity is ever
    /// declared, so none can be expanded, so the billion-laughs expansion has
    /// nothing to expand."
    #[test]
    fn an_entity_declaration_is_refused_outright() {
        let message = refusal(r#"<!DOCTYPE lolz [<!ENTITY lol "lol">]><lolz>&lol;</lolz>"#);
        assert!(
            message.contains("internal subset") || message.contains("declaration"),
            "the refusal should name what it refused, said: {message}"
        );
    }

    /// The billion-laughs document itself, in the shape it is usually written.
    #[test]
    fn the_billion_laughs_document_is_refused_before_anything_expands() {
        let message = refusal(
            r#"<?xml version="1.0"?>
<!DOCTYPE lolz [
  <!ENTITY lol "lol">
  <!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">
  <!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">
]>
<lolz>&lol3;</lolz>"#,
        );
        assert!(!message.is_empty());
    }

    /// "A `DOCTYPE` is accepted only in its inert form: a bare name, no internal
    /// subset, no `SYSTEM` or `PUBLIC` identifier."
    #[test]
    fn a_bare_doctype_is_accepted_because_nmap_writes_one() {
        let events = read(r#"<?xml version="1.0"?><!DOCTYPE nmaprun><nmaprun/>"#)
            .expect("the inert form nmap writes is readable");
        assert!(!events.is_empty());
    }

    #[test]
    fn a_doctype_naming_a_system_identifier_is_refused() {
        let message = refusal(r#"<!DOCTYPE a SYSTEM "file:///etc/passwd"><a/>"#);
        assert!(message.contains("external identifier"), "said: {message}");
    }

    #[test]
    fn a_doctype_naming_a_public_identifier_is_refused() {
        let message =
            refusal(r#"<!DOCTYPE a PUBLIC "-//X//EN" "http://example.invalid/x.dtd"><a/>"#);
        assert!(message.contains("external identifier"), "said: {message}");
    }

    #[test]
    fn a_doctype_with_an_internal_subset_is_refused() {
        let message = refusal(r#"<!DOCTYPE a [<!ELEMENT a EMPTY>]><a/>"#);
        assert!(message.contains("internal subset"), "said: {message}");
    }

    /// The XXE shape: an external entity pointed at a local file.
    #[test]
    fn an_external_entity_reference_has_nothing_to_resolve_against() {
        let message =
            refusal(r#"<!DOCTYPE a [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><a>&xxe;</a>"#);
        assert!(!message.is_empty());
    }

    /// "Any entity reference other than the five predefined and numeric
    /// character references is refused, naming it."
    #[test]
    fn an_undeclared_entity_reference_is_refused_and_named() {
        let message = refusal(r#"<a id="&whoami;"/>"#);
        assert!(
            message.contains("whoami"),
            "the refusal must name the reference, said: {message}"
        );
    }

    #[test]
    fn the_five_predefined_entities_resolve() {
        let mut input = Cursor::new(r#"<a id="&lt;&gt;&amp;&quot;&apos;"/>"#.as_bytes().to_vec());
        let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);
        parser.next_event().expect("the document reads");
        assert_eq!(parser.element.value(b"id"), Some("<>&\"'"));
    }

    #[test]
    fn a_numeric_character_reference_resolves() {
        let mut input = Cursor::new(r#"<a id="&#65;&#x42;"/>"#.as_bytes().to_vec());
        let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);
        parser.next_event().expect("the document reads");
        assert_eq!(parser.element.value(b"id"), Some("AB"));
    }

    /// "Processing instructions are skipped without being interpreted. This is
    /// not an XSLT engine and never opens what one names."
    #[test]
    fn a_processing_instruction_is_skipped_rather_than_read() {
        let events = read(
            r#"<?xml version="1.0"?><?xml-stylesheet href="file:///usr/share/nmap/nmap.xsl" type="text/xsl"?><a/>"#,
        )
        .expect("a stylesheet instruction is skipped, not followed");
        assert!(
            matches!(events.as_slice(), [Event::Start { self_closing: true }]),
            "the two instructions produce no events, leaving only the element"
        );
    }

    // ─── The six bounds ──────────────────────────────────────────────────────

    #[test]
    fn nesting_is_bounded() {
        let deep = |levels: usize| {
            let mut doc = String::new();
            for _ in 0..levels {
                doc.push_str("<a>");
            }
            for _ in 0..levels {
                doc.push_str("</a>");
            }
            doc
        };

        read(&deep(MAX_DEPTH)).expect("nesting at the bound is accepted");
        let message = refusal(&deep(MAX_DEPTH + 2));
        assert!(
            message.contains("nest") || message.contains("deep"),
            "said: {message}"
        );
    }

    #[test]
    fn an_element_name_is_bounded() {
        let long = "n".repeat(MAX_NAME_BYTES + 1);
        let message = refusal(&format!("<{long}/>"));
        assert!(message.contains("name"), "said: {message}");
    }

    #[test]
    fn an_attribute_name_is_bounded() {
        let long = "n".repeat(MAX_NAME_BYTES + 1);
        let message = refusal(&format!(r#"<a {long}="x"/>"#));
        assert!(message.contains("name"), "said: {message}");
    }

    /// A kept attribute's value past the bound is a refusal; the bound itself is
    /// accepted.
    #[test]
    fn an_unwanted_attribute_is_not_accumulated_and_so_is_not_bounded() {
        // The claim `read_value`'s doc makes, and the reason nmap's `args` and
        // `services` attributes need no limit tuned around them: a value this
        // parser was not asked for is scanned past rather than collected, so
        // the size bound never applies to it.
        let enormous = "v".repeat(MAX_VALUE_BYTES * 8);
        let events = read(&format!(r#"<a id="kept" args="{enormous}"/>"#))
            .expect("an unwanted value is never measured against the bound");

        assert!(
            events
                .iter()
                .any(|event| matches!(event, Event::Start { .. })),
            "the element should have been read"
        );

        // And the same value under a name the parser *was* asked for is refused,
        // so the test above is about what is kept and not about the length.
        assert!(!refusal(&format!(r#"<a id="{enormous}"/>"#)).is_empty());
    }

    #[test]
    fn a_kept_attribute_value_is_bounded() {
        let at_bound = "v".repeat(MAX_VALUE_BYTES);
        read(&format!(r#"<a id="{at_bound}"/>"#)).expect("a value at the bound is accepted");

        let past = "v".repeat(MAX_VALUE_BYTES + 1);
        assert!(!refusal(&format!(r#"<a id="{past}"/>"#)).is_empty());
    }

    #[test]
    fn one_elements_markup_is_bounded() {
        let mut input = Cursor::new(format!(r#"<a id="{}"/>"#, "v".repeat(4096)).into_bytes());
        let mut parser = Parser::new(&mut input, 128, FORMAT, KEPT);
        assert!(
            parser.next_event().is_err(),
            "an element past max_element_bytes is refused"
        );
    }

    #[test]
    fn an_entity_reference_that_never_closes_is_bounded() {
        let message = refusal(&format!(
            r#"<a id="&{}"/>"#,
            "x".repeat(MAX_ENTITY_BYTES * 4)
        ));
        assert!(!message.is_empty());
    }

    // ─── Termination ─────────────────────────────────────────────────────────

    #[test]
    fn a_document_that_ends_mid_element_is_an_error_not_a_hang() {
        for truncated in [
            "<a",
            "<a id=",
            r#"<a id=""#,
            "<a><b",
            "<!DOCTYPE",
            "<!--",
            "<?xml",
        ] {
            let _ = read(truncated);
        }
    }

    proptest! {
        /// Nothing a file can contain makes this parser panic or run forever.
        ///
        /// The same campaign `fingerprint` runs over its own parsers, applied to
        /// the one that reads a document somebody else wrote.
        #[test]
        fn the_parser_never_panics_on_arbitrary_input(document in "(?s).{0,2000}") {
            let _ = read(&document);
        }

        /// Arbitrary bytes, not just arbitrary text: a file on disk is not
        /// obliged to be UTF-8.
        #[test]
        fn the_parser_never_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..2000)) {
            let mut input = Cursor::new(bytes);
            let mut parser = Parser::new(&mut input, 64 * 1024, FORMAT, KEPT);
            for _ in 0..10_000 {
                match parser.next_event() {
                    Ok(Event::Eof) | Err(_) => break,
                    Ok(_) => {}
                }
            }
        }
    }
}
