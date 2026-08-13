// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Reading nmap's XML as targets
//!
//! The file somebody already has. `-oX` is what gets saved into an engagement
//! repository, so reading it is how a previous scan - nmap's or this engine's,
//! since [`crate::export::nmap`] writes the same format - becomes the target
//! list for the next one, hosts and per-host ports together.
//!
//! ## The refusals are the security control
//!
//! This is a hand-rolled parser reading a file somebody else wrote. What makes
//! that defensible is not care in the parsing; it is that the dangerous
//! constructs have no representation here at all.
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
//! - Nesting depth, element count, name length and attribute length are all
//!   bounded, and one element's markup is bounded by
//!   [`ImportLimits::max_line_bytes`].
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
//! and a rule that turned all three away would have left this module unable to
//! read its own subject. `<!DOCTYPE nmaprun>` declares nothing and references
//! nothing; it is inert. The narrower rule is also the stronger one, because a
//! blanket refusal is the kind that acquires an option to disable it the first
//! time somebody needs their file read.
//!
//! ## What it reads
//!
//! Seven element names, and every other element is ignored without its content
//! being examined:
//!
//! | Element | Read for |
//! |---|---|
//! | `nmaprun` | that this is the format at all |
//! | `host` | grouping addresses with the ports found on them |
//! | `address` | `addr`, when `addrtype` is `ipv4` or `ipv6` |
//! | `ports`, `port` | `protocol` and `portid` |
//! | `state`, `hostnames` | nothing; named so their content is skipped knowingly |
//!
//! A hardware address is skipped: a MAC is not something to scan. Hostnames are
//! skipped too, because every nmap host record carries an address and resolving
//! a name again would be work with a worse answer.
//!
//! Ports are not filtered by state, for the same reason [`super::json`] does not
//! filter: the file is the caller's own selection, and "rescan what nmap found"
//! should not quietly mean "rescan some of it".

use std::io::BufRead;

use crate::import::{ImportError, ImportLimits, Importer, Origin, TargetSink};

/// The format's name in errors.
const FORMAT: &str = "nmap XML";

/// How deeply elements may nest.
///
/// Real nmap output reaches five. Sixty-four is unreachable by anything honest
/// and bounds the parser's own bookkeeping, which is the only thing depth costs
/// here - element content is never accumulated.
const MAX_DEPTH: usize = 64;

/// The longest element or attribute name accepted, in bytes.
const MAX_NAME_BYTES: usize = 64;

/// The longest attribute value kept, in bytes.
///
/// Applies only to the four attributes this parser reads, all of which are an
/// address or a port number. Every other attribute is scanned past without
/// being stored, which is what lets nmap's very long `args` and `services`
/// attributes through without a limit tuned around them.
const MAX_VALUE_BYTES: usize = 256;

/// The most elements one document may contain.
const MAX_ELEMENTS: u64 = 1 << 24;

/// The longest entity reference accepted, in bytes, including `&` and `;`.
const MAX_ENTITY_BYTES: usize = 16;

/// Reads an nmap XML document as targets.
#[derive(Debug, Clone, Copy, Default)]
pub struct NmapXmlImporter {
    limits: ImportLimits,
}

impl NmapXmlImporter {
    /// A reader bounded by `limits`.
    pub fn new(limits: ImportLimits) -> Self {
        Self { limits }
    }
}

impl Importer for NmapXmlImporter {
    fn import(
        &self,
        input: &mut dyn BufRead,
        sink: &mut dyn TargetSink,
    ) -> Result<(), ImportError> {
        let mut parser = Parser::new(input, self.limits.max_line_bytes);
        let mut host: Option<Accumulator> = None;
        let mut depth = 0usize;
        let mut saw_root = false;
        let mut token = String::new();

        loop {
            match parser.next_event()? {
                Event::Eof => break,

                Event::Start { self_closing } => {
                    if !self_closing {
                        depth += 1;
                        if depth > MAX_DEPTH {
                            return Err(parser
                                .malformed(format!("elements nested more than {MAX_DEPTH} deep")));
                        }
                    }

                    match parser.element.name.as_slice() {
                        b"nmaprun" => saw_root = true,
                        b"host" => host = Some(Accumulator::default()),
                        b"address" => {
                            if let Some(accumulator) = host.as_mut() {
                                accumulator.address(&parser.element)?;
                            }
                        }
                        b"port" => {
                            if let Some(accumulator) = host.as_mut() {
                                accumulator.port(&parser.element, &parser)?;
                            }
                        }
                        _ => {}
                    }

                    // A self-closing `<host/>` opens and closes in one event.
                    if self_closing && parser.element.name == b"host" {
                        emit(host.take(), sink, &mut token, parser.origin())?;
                    }
                }

                Event::End => {
                    depth = depth.saturating_sub(1);
                    if parser.element.name == b"host" {
                        emit(host.take(), sink, &mut token, parser.origin())?;
                    }
                }
            }
        }

        if !saw_root {
            return Err(ImportError::Malformed {
                format: FORMAT,
                origin: Origin::unknown(),
                message: "no <nmaprun> element: this is not an nmap document".to_string(),
            });
        }

        Ok(())
    }
}

/// One host's addresses and ports, gathered until its element closes.
#[derive(Debug, Default)]
struct Accumulator {
    addresses: Vec<String>,
    /// Port number and whether it is UDP, in the order the document listed them.
    ports: Vec<(u16, bool)>,
}

impl Accumulator {
    /// Takes an `<address>` element, if it names something scannable.
    fn address(&mut self, element: &Element) -> Result<(), ImportError> {
        // A hardware address is not a target, and neither is an address type
        // this build has never heard of.
        let kind = element.value(b"addrtype").unwrap_or("");
        if kind != "ipv4" && kind != "ipv6" {
            return Ok(());
        }

        if let Some(address) = element.value(b"addr")
            && !address.is_empty()
        {
            self.addresses.push(address.to_string());
        }

        Ok(())
    }

    /// Takes a `<port>` element.
    fn port(&mut self, element: &Element, parser: &Parser<'_>) -> Result<(), ImportError> {
        let Some(number) = element.value(b"portid") else {
            return Ok(());
        };
        let number: u16 = number
            .parse()
            .map_err(|_| parser.malformed(format!("'{number}' is not a port number")))?;

        let protocol = element.value(b"protocol").unwrap_or("tcp");
        let udp = match protocol {
            "tcp" => false,
            "udp" => true,
            // Not skippable, for the reason `super::json` gives: a transport
            // this build cannot name is a port it cannot probe correctly, and
            // reading it as TCP would scan something else and call it a
            // success.
            other => {
                return Err(parser.malformed(format!(
                    "port {number} names transport '{other}', which this build cannot probe"
                )));
            }
        };

        self.ports.push((number, udp));
        Ok(())
    }
}

/// Turns one finished host into targets.
fn emit(
    host: Option<Accumulator>,
    sink: &mut dyn TargetSink,
    token: &mut String,
    origin: Origin,
) -> Result<(), ImportError> {
    let Some(host) = host else {
        return Ok(());
    };

    let mut ports = String::new();
    for (number, udp) in &host.ports {
        if !ports.is_empty() {
            ports.push(',');
        }
        if *udp {
            ports.push_str("u:");
        }
        ports.push_str(&number.to_string());
    }

    for address in &host.addresses {
        token.clear();
        if ports.is_empty() {
            token.push_str(address);
        } else {
            // Bracketed unconditionally, for the reason the CSV and JSON
            // readers give: `10.0.0.1:u:53` is a token with two colons in it,
            // which the grammar reads as an IPv6 address.
            token.push('[');
            token.push_str(address);
            token.push_str("]:");
            token.push_str(&ports);
        }
        sink.accept(token, origin)?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// The parser
// ---------------------------------------------------------------------------

/// What the parser found.
enum Event {
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
struct Element {
    name: Vec<u8>,
    values: Vec<(Vec<u8>, Vec<u8>)>,
}

impl Element {
    fn clear(&mut self) {
        self.name.clear();
        self.values.clear();
    }

    /// One attribute's value as text, if the element carried it.
    fn value(&self, name: &[u8]) -> Option<&str> {
        self.values
            .iter()
            .find(|(key, _)| key == name)
            .and_then(|(_, value)| std::str::from_utf8(value).ok())
    }
}

/// The attributes worth keeping. Everything else is skipped unbuffered.
const KEPT_ATTRIBUTES: [&[u8]; 4] = [b"addr", b"addrtype", b"protocol", b"portid"];

struct Parser<'a> {
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
    element: Element,
}

impl<'a> Parser<'a> {
    fn new(input: &'a mut dyn BufRead, max_element_bytes: usize) -> Self {
        Self {
            input,
            buffer: Vec::new(),
            position: 0,
            line: 1,
            element_bytes: 0,
            max_element_bytes,
            elements: 0,
            element: Element::default(),
        }
    }

    fn origin(&self) -> Origin {
        Origin::line(self.line)
    }

    fn malformed(&self, message: String) -> ImportError {
        ImportError::Malformed {
            format: FORMAT,
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
    fn next_event(&mut self) -> Result<Event, ImportError> {
        loop {
            // Text between elements is never read. Nothing here needs it, and
            // not reading it is what makes an entity reference in content
            // harmless whatever it says.
            loop {
                match self.peek()? {
                    None => return Ok(Event::Eof),
                    Some(b'<') => break,
                    Some(_) => {
                        self.element_bytes = 0;
                        self.bump()?;
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

        let keep = KEPT_ATTRIBUTES.contains(&name.as_slice());
        let value = self.read_value(keep)?;
        if keep {
            self.element.values.push((name, value));
        }

        Ok(())
    }

    /// Reads a quoted attribute value.
    ///
    /// `keep` decides whether the bytes are stored or merely scanned past. An
    /// unwanted value is not accumulated at all, which is what lets nmap's very
    /// long `args` and `services` attributes through without any limit tuned
    /// around them - only the element's total markup is bounded.
    fn read_value(&mut self, keep: bool) -> Result<Vec<u8>, ImportError> {
        let Some(quote) = self.peek()? else {
            return Err(self.malformed("the document ends inside a tag".to_string()));
        };
        if quote != b'"' && quote != b'\'' {
            return Err(self.malformed("an attribute value that is not quoted".to_string()));
        }
        self.bump()?;

        let mut value = Vec::new();
        loop {
            let Some(byte) = self.peek()? else {
                return Err(
                    self.malformed("the document ends inside an attribute value".to_string())
                );
            };

            if byte == quote {
                self.bump()?;
                return Ok(value);
            }

            if byte == b'&' {
                let resolved = self.entity()?;
                if keep {
                    push_bounded(&mut value, &resolved, self)?;
                }
                continue;
            }

            self.bump()?;
            if keep {
                push_bounded(&mut value, &[byte], self)?;
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
    fn skip_until(&mut self, terminator: &[u8]) -> Result<(), ImportError> {
        let mut matched = 0usize;
        loop {
            let Some(byte) = self.bump()? else {
                return Err(self.malformed(format!(
                    "the document ends before '{}'",
                    String::from_utf8_lossy(terminator)
                )));
            };

            if byte == terminator[matched] {
                matched += 1;
                if matched == terminator.len() {
                    return Ok(());
                }
            } else {
                // Restart, allowing for the byte itself starting a fresh match.
                matched = usize::from(byte == terminator[0]);
            }
        }
    }
}

/// Appends to a kept attribute value, bounded.
fn push_bounded(value: &mut Vec<u8>, bytes: &[u8], parser: &Parser<'_>) -> Result<(), ImportError> {
    if value.len() + bytes.len() > MAX_VALUE_BYTES {
        return Err(parser.malformed(format!(
            "an attribute value longer than {MAX_VALUE_BYTES} bytes"
        )));
    }
    value.extend_from_slice(bytes);
    Ok(())
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
// ║    ██║   ███████╗███████║   ██║   ███████║ ║
// ║    ╚═╝   ╚══════╝╚══════╝   ╚═╝   ╚══════╝ ║
// ╚════════════════════════════════════════════╝

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::models::port::PortSet;
    use crate::import::{ImportFormat, ImportOptions, Imported};
    use std::io::Cursor;

    /// The preamble every real nmap file opens with, and which the refusal rule
    /// as first drafted would have rejected in its entirety.
    const REAL_PREAMBLE: &str = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<!DOCTYPE nmaprun>\n",
        "<?xml-stylesheet href=\"file:///usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?>\n",
        "<!-- Nmap 7.99 scan initiated Tue Aug 11 19:09:27 2026 as: nmap -oX out.xml -->\n",
    );

    fn options() -> ImportOptions<'static> {
        ImportOptions::new(PortSet::try_from("80").unwrap())
    }

    fn read(input: &str) -> Result<Imported, ImportError> {
        ImportFormat::NmapXml.read(&mut Cursor::new(input), &options())
    }

    /// The whole point: a file nmap actually writes, preamble and all.
    #[test]
    fn a_real_nmap_document_reads_as_its_hosts_and_ports() {
        let document = format!(
            "{REAL_PREAMBLE}{}",
            concat!(
                r#"<nmaprun scanner="nmap" args="nmap -oX out.xml 10.0.0.0/24" start="1786468167" version="7.99" xmloutputversion="1.05">"#,
                "\n<scaninfo type=\"syn\" protocol=\"tcp\" numservices=\"1000\" services=\"1,3-4,6-7,9,13,17,19-26\"/>\n",
                "<verbose level=\"0\"/>\n<debugging level=\"0\"/>\n",
                "<host starttime=\"1\" endtime=\"2\">\n",
                "<status state=\"up\" reason=\"echo-reply\" reason_ttl=\"64\"/>\n",
                "<address addr=\"10.0.0.1\" addrtype=\"ipv4\"/>\n",
                "<address addr=\"aa:bb:cc:dd:ee:ff\" addrtype=\"mac\" vendor=\"Arris\"/>\n",
                "<hostnames>\n<hostname name=\"router.lan\" type=\"PTR\"/>\n</hostnames>\n",
                "<ports>\n",
                "<extraports state=\"closed\" count=\"998\"><extrareasons reason=\"resets\" count=\"998\"/></extraports>\n",
                "<port protocol=\"tcp\" portid=\"22\"><state state=\"open\" reason=\"syn-ack\" reason_ttl=\"64\"/><service name=\"ssh\" product=\"OpenSSH\" method=\"probed\" conf=\"10\"/></port>\n",
                "<port protocol=\"udp\" portid=\"53\"><state state=\"open\" reason=\"udp-response\"/></port>\n",
                "</ports>\n<times srtt=\"39\" rttvar=\"5000\" to=\"100000\"/>\n</host>\n",
                "<host><status state=\"up\" reason=\"conn-refused\"/><address addr=\"2001:db8::1\" addrtype=\"ipv6\"/></host>\n",
                "<runstats><finished time=\"3\" elapsed=\"0.01\" exit=\"success\"/><hosts up=\"2\" down=\"0\" total=\"2\"/></runstats>\n",
                "</nmaprun>\n",
            )
        );

        let imported = read(&document).expect("a real nmap document reads");

        assert_eq!(imported.addresses, 2, "one IPv4 host and one IPv6 host");
        assert!(
            imported
                .map
                .units
                .iter()
                .any(|unit| unit.ports().has_tcp(22) && unit.ports().has_udp(53)),
            "the ports nmap found have to come back on the host it found them on"
        );
        // The MAC is not a target, and the portless host takes the defaults.
        assert!(
            imported
                .map
                .units
                .iter()
                .any(|unit| unit.ports().has_tcp(80)),
            "the host with no ports takes the caller's defaults"
        );
    }

    /// The rule as first drafted refused any DOCTYPE and any processing
    /// instruction, which would have rejected 100% of real nmap output. This is
    /// the test that would have caught it.
    #[test]
    fn the_preamble_nmap_actually_writes_is_accepted() {
        let document = format!(
            "{REAL_PREAMBLE}<nmaprun><host><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/></host></nmaprun>"
        );

        assert_eq!(read(&document).expect("accepted").addresses, 1);
    }

    /// Billion laughs. Not mitigated - unrepresentable, because the declaration
    /// it needs is refused before any expansion could be considered.
    #[test]
    fn an_entity_declaration_is_refused_outright() {
        let document = concat!(
            r#"<?xml version="1.0"?>"#,
            "\n<!DOCTYPE nmaprun [\n",
            "  <!ENTITY lol \"lol\">\n",
            "  <!ENTITY lol2 \"&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;\">\n",
            "  <!ENTITY lol3 \"&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;\">\n",
            "]>\n",
            r#"<nmaprun><host><address addr="&lol3;" addrtype="ipv4"/></host></nmaprun>"#,
        );

        let error = read(document).expect_err("an internal subset is refused");
        let message = error.to_string();
        assert!(
            message.contains("internal subset"),
            "the refusal has to say what it refused: {message}"
        );
    }

    /// External entity: the file-disclosure shape. Refused at the DOCTYPE,
    /// before anything could be fetched.
    #[test]
    fn an_external_entity_is_refused_at_the_doctype() {
        for document in [
            concat!(
                r#"<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>"#,
                r#"<nmaprun><host><address addr="&xxe;" addrtype="ipv4"/></host></nmaprun>"#,
            ),
            concat!(
                r#"<!DOCTYPE nmaprun SYSTEM "http://example.invalid/evil.dtd">"#,
                r#"<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>"#,
            ),
            concat!(
                r#"<!DOCTYPE nmaprun PUBLIC "-//x//y" "http://example.invalid/evil.dtd">"#,
                r#"<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/></host></nmaprun>"#,
            ),
        ] {
            let error = read(document).expect_err("refused");
            assert!(matches!(error, ImportError::Malformed { .. }), "{error:?}");
        }
    }

    /// With no declarations permitted, a reference to anything but the five
    /// predefined entities cannot have been defined - so it is named rather
    /// than quietly dropped.
    #[test]
    fn an_undeclared_entity_reference_is_refused_naming_it() {
        let document =
            r#"<nmaprun><host><address addr="&secret;" addrtype="ipv4"/></host></nmaprun>"#;

        let message = read(document).expect_err("refused").to_string();
        assert!(message.contains("secret"), "{message}");
    }

    /// The five that are always defined, and numeric references, do resolve -
    /// a parser that refused those would not be reading XML.
    #[test]
    fn the_predefined_and_numeric_references_resolve() {
        // Not an address, so it fails in the grammar rather than the parser,
        // which is what proves the text arrived decoded.
        let document =
            r#"<nmaprun><host><address addr="a&amp;b&#65;" addrtype="ipv4"/></host></nmaprun>"#;

        let message = read(document)
            .expect_err("'a&bA' is not an address")
            .to_string();
        assert!(
            message.contains("a&bA"),
            "the entity was not resolved: {message}"
        );
    }

    #[test]
    fn a_document_that_is_not_nmaps_is_refused() {
        let message = read("<rss><channel><item/></channel></rss>")
            .expect_err("not an nmap document")
            .to_string();
        assert!(message.contains("nmaprun"), "{message}");
    }

    /// Unbounded nesting is the other way a parser can be made to work forever.
    #[test]
    fn nesting_past_the_limit_is_refused() {
        let deep = format!(
            "<nmaprun>{}{}</nmaprun>",
            "<a>".repeat(MAX_DEPTH + 8),
            "</a>".repeat(MAX_DEPTH + 8)
        );

        let error = read(&deep).expect_err("refused");
        assert!(error.to_string().contains("nested"), "{error}");
    }

    /// An element whose markup runs away has to be refused rather than
    /// accumulated, and it is the one bound a caller can set.
    #[test]
    fn an_element_past_the_byte_limit_is_refused() {
        let options = options().with_limits(ImportLimits {
            max_line_bytes: 256,
            ..ImportLimits::default()
        });
        let runaway = format!("<nmaprun><host attr=\"{}\"/></nmaprun>", "x".repeat(4096));

        assert!(matches!(
            ImportFormat::NmapXml.read(&mut Cursor::new(runaway), &options),
            Err(ImportError::LineTooLong { .. })
        ));
    }

    /// Nmap's `args` and `services` attributes are genuinely long, and this
    /// parser must not be bounded in a way that rejects them - which is why an
    /// unwanted value is never accumulated.
    #[test]
    fn a_long_attribute_this_parser_ignores_is_not_a_problem() {
        let services: String = (1..2000).map(|port| format!("{port},")).collect();
        let document = format!(
            "<nmaprun><scaninfo services=\"{services}\"/>\
             <host><address addr=\"10.0.0.1\" addrtype=\"ipv4\"/></host></nmaprun>"
        );

        assert_eq!(read(&document).expect("reads").addresses, 1);
    }

    /// An unrecognised transport is not skippable, for the reason the JSON
    /// reader gives: reading it as TCP would probe something else and report
    /// success.
    #[test]
    fn an_unknown_transport_is_refused() {
        let document = concat!(
            r#"<nmaprun><host><address addr="10.0.0.1" addrtype="ipv4"/>"#,
            r#"<ports><port protocol="sctp" portid="9"><state state="open"/></port></ports>"#,
            r#"</host></nmaprun>"#,
        );

        let message = read(document).expect_err("refused").to_string();
        assert!(message.contains("sctp"), "{message}");
    }

    #[test]
    fn an_empty_document_is_refused_and_a_hostless_one_is_not() {
        assert!(read("").is_err(), "nothing is not an nmap document");

        let imported = read("<nmaprun><runstats/></nmaprun>").expect("a scan that found nothing");
        assert_eq!(imported.tokens, 0);
        assert!(imported.map.is_empty());
    }

    /// Reads a document this crate did not write.
    ///
    /// Every other test here parses a document typed into this file, which
    /// makes them an instrument carrying whoever wrote them's beliefs about
    /// nmap's output - the trap this project keeps finding. This one reads a
    /// file nmap produced:
    ///
    /// ```text
    /// nmap -oX /tmp/real.xml -sV -p 1-1000 192.168.0.1
    /// ZOND_NMAP_XML=/tmp/real.xml cargo test --features import-nmap \
    ///   a_file_nmap_itself_wrote -- --ignored --nocapture
    /// ```
    ///
    /// Worth re-running whenever nmap's output version moves.
    #[test]
    #[ignore = "needs a real nmap file named by ZOND_NMAP_XML"]
    fn a_file_nmap_itself_wrote() {
        let path =
            std::env::var("ZOND_NMAP_XML").expect("set ZOND_NMAP_XML to a file nmap produced");
        let document = std::fs::read_to_string(&path).expect("the file is readable");

        let imported = ImportFormat::NmapXml
            .read(&mut Cursor::new(document), &options())
            .expect("a file nmap wrote has to read");

        println!(
            "{path}: {} addresses, {} refused",
            imported.addresses,
            imported.refusals.len()
        );
        for unit in &imported.map.units {
            let ports: Vec<String> = unit
                .ports()
                .iter()
                .map(|(number, protocol)| format!("{number}/{protocol:?}"))
                .collect();
            println!("  {} addresses on {}", unit.ips().len(), ports.join(", "));
        }
        assert!(
            imported.addresses > 0,
            "a real scan's output produced no targets at all"
        );
    }

    /// The round trip, held against the fixture rather than against the
    /// document: the fixture's `Host` values sit outside the serialization loop
    /// entirely, so the exporter and importer cannot be wrong together.
    #[cfg(feature = "export-nmap")]
    #[test]
    fn a_document_this_engine_wrote_reads_back_as_its_own_targets() {
        use crate::export::{ExportOptions, Exporter, NmapXmlExporter};
        use std::collections::BTreeSet;

        let report = crate::export::fixture::report();

        let mut expected: BTreeSet<(String, u16)> = BTreeSet::new();
        for host in report.hosts() {
            for ip in host.ips() {
                if host.port_count() == 0 {
                    expected.insert((ip.to_string(), 80));
                    continue;
                }
                for port in host.ports() {
                    expected.insert((ip.to_string(), port.number()));
                }
            }
        }

        let mut document = Vec::new();
        NmapXmlExporter::new(ExportOptions::new())
            .export(&report, &mut document)
            .expect("the fixture exports");

        let imported = ImportFormat::NmapXml
            .read(&mut Cursor::new(document), &options())
            .expect("this engine reads back what it wrote");

        let mut found: BTreeSet<(String, u16)> = BTreeSet::new();
        for target in imported.map.iter() {
            found.insert((target.ip.to_string(), target.port));
        }

        assert_eq!(
            found, expected,
            "the hosts and ports the scan found are not the ones that came back"
        );
        assert!(
            !expected.is_empty(),
            "a fixture with no ports proves nothing"
        );
    }
}
