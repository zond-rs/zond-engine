// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # What every exporter writes through
//!
//! The pieces more than one format needs and none of them owns: the escaper
//! every page puts report text through, the scaffolding a report page and a
//! comparison page both wear, and the one mapping from a `serde_json` failure
//! onto [`ExportError`].
//!
//! ## What belongs here
//!
//! A piece two writers would otherwise each keep a copy of, whose output is
//! fixed rather than a choice the format makes. The escaper is the clearest
//! case: two escapers means one of them gets a fix and the other does not, and
//! the one that does not is a hostname that executes on whoever opened the
//! report.
//!
//! ## What does not
//!
//! Anything that decides what a document says. Each format keeps its own markup,
//! its own order and its own vocabulary, and borrows only the pieces that have
//! one right spelling. Nor does anything a single format is the only caller of.
//!
//! ## Features
//!
//! Every item is gated by the formats that call it and by nothing wider, so
//! sharing a module does not make `export-csv` compile a stylesheet or
//! `export-html` compile `serde_json`. `cargo hack check --each-feature` holds
//! the gates honest.

#[cfg(feature = "export-html")]
use std::fmt::{self, Write as _};
#[cfg(feature = "export-html")]
use std::io::Write;

use crate::export::ExportError;
#[cfg(feature = "export-html")]
use crate::export::schema::ENGINE_NAME;

// ---------------------------------------------------------------------------
// Escaping, for every page this crate writes
// ---------------------------------------------------------------------------

/// Report text, escaped for a page as it is written.
///
/// Everything a scanned network chose to call itself passes through here.
/// Beyond the five characters that carry markup, the bidirectional set is
/// rendered as code points rather than emitted, since a hostname that reverses
/// the text after it makes a report display one thing and mean another. The
/// remaining control characters are shown the same way, so that what a report
/// claims to have found stays legible as bytes.
///
/// This writes markup, so it belongs in element content and nowhere else. No
/// writer in this crate puts a report value into an attribute.
#[cfg(feature = "export-html")]
pub(crate) struct Text<'a>(pub(crate) &'a str);

#[cfg(feature = "export-html")]
impl fmt::Display for Text<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            match character {
                '&' => f.write_str("&amp;")?,
                '<' => f.write_str("&lt;")?,
                '>' => f.write_str("&gt;")?,
                '"' => f.write_str("&quot;")?,
                '\'' => f.write_str("&#39;")?,
                character if is_neutralized(character) => write!(
                    f,
                    "<span class=\"ctl\">U+{:04X}</span>",
                    u32::from(character)
                )?,
                character => f.write_char(character)?,
            }
        }
        Ok(())
    }
}

/// Report text for somewhere markup cannot go.
///
/// A document's title is text, not content: a `<span>` written into it renders
/// as its own source. A neutralized character becomes the replacement character
/// instead.
#[cfg(feature = "export-html")]
pub(crate) struct Plain<'a>(pub(crate) &'a str);

#[cfg(feature = "export-html")]
impl fmt::Display for Plain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for character in self.0.chars() {
            match character {
                '&' => f.write_str("&amp;")?,
                '<' => f.write_str("&lt;")?,
                '>' => f.write_str("&gt;")?,
                '"' => f.write_str("&quot;")?,
                '\'' => f.write_str("&#39;")?,
                character if is_neutralized(character) => f.write_char('\u{fffd}')?,
                character => f.write_char(character)?,
            }
        }
        Ok(())
    }
}

/// Whether a character is shown as its code point rather than emitted.
///
/// The bidirectional formatting characters reorder the text around them and a
/// reader cannot see they are there. The control characters are included because
/// a page renders them as nothing, so a banner containing one would silently
/// lose it.
///
/// Tab, newline and carriage return pass through. They are ordinary whitespace
/// in HTML and a script's multi-line output is worth keeping the shape of.
#[cfg(feature = "export-html")]
fn is_neutralized(character: char) -> bool {
    matches!(character,
        '\u{0}'..='\u{8}'
        | '\u{b}' | '\u{c}'
        | '\u{e}'..='\u{1f}'
        | '\u{7f}'..='\u{9f}'
        | '\u{61c}'
        | '\u{200e}' | '\u{200f}'
        | '\u{202a}'..='\u{202e}'
        | '\u{2066}'..='\u{2069}')
}

/// Escapes one value into markup.
#[cfg(feature = "export-html")]
pub(crate) fn esc(text: &str) -> String {
    Text(text).to_string()
}

// ---------------------------------------------------------------------------
// The stylesheet, and the vocabulary it defines
// ---------------------------------------------------------------------------

/// The stylesheet inlined into every page this crate writes.
///
/// A file of its own rather than a string in a source file, so it is edited as a
/// stylesheet. A test pins the class names it defines to the ones the report
/// page writes.
#[cfg(feature = "export-html")]
pub(crate) const STYLE: &str = include_str!("../../assets/html/report.css");

/// Something is there and answering: `up`, `open`, a host that appeared.
///
/// Four tones rather than one colour per state name. The state's name is always
/// printed beside its colour, so the colour carries something else: how much the
/// finding is worth a second look.
#[cfg(feature = "export-html")]
pub(crate) const TONE_FOUND: &str = "s-found";

/// Something is there and the scan could not pin it down. Drawn hatched as well
/// as coloured, because green against amber is the pair a colour-blind reader
/// loses first and a printed report is often greyscale.
#[cfg(feature = "export-html")]
pub(crate) const TONE_PARTIAL: &str = "s-partial";

/// A definite negative: `down`, `closed`. Real evidence, and rarely what the
/// reader came for.
#[cfg(feature = "export-html")]
pub(crate) const TONE_INERT: &str = "s-inert";

/// Nothing was established at all.
#[cfg(feature = "export-html")]
pub(crate) const TONE_NONE: &str = "s-none";

// ---------------------------------------------------------------------------
// Page scaffolding
// ---------------------------------------------------------------------------

/// The head, the stylesheet, the theme checkbox, and the open page container.
///
/// Takes no report. The `generator` is what wrote the page, which is this build
/// whoever the findings came from; who that was belongs in the page's own
/// colophon, the one part of the frame each format writes for itself.
#[cfg(feature = "export-html")]
pub(crate) fn head(out: &mut dyn Write, title: &str) -> Result<(), ExportError> {
    writeln!(
        out,
        r#"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="{engine} {version}">
<meta name="robots" content="noindex, nofollow">
<title>{title}</title>
<style>
{style}</style>
</head>
<body>
<input type="checkbox" id="zond-theme" class="theme-switch" aria-label="Use the other colour scheme">
<div class="sheet">"#,
        engine = ENGINE_NAME,
        version = crate::report::ENGINE_VERSION,
        title = Plain(title),
        style = STYLE,
    )?;
    Ok(())
}

/// The brand, the heading and the theme control, around a one-line subtitle.
///
/// `subtitle` is markup the caller escaped: what a page says about itself under
/// its own heading is the page's business, and only the frame around it is
/// shared.
#[cfg(feature = "export-html")]
pub(crate) fn masthead(
    out: &mut dyn Write,
    heading: &str,
    subtitle: &str,
) -> Result<(), ExportError> {
    writeln!(
        out,
        r#"<header class="masthead">
<div class="brand">zond<span class="brand-mark">_</span></div>
<div class="masthead-title">
<h1>{heading}</h1>
<p class="subtitle">{subtitle}</p>
</div>
<label class="theme-label" for="zond-theme" title="Switch between light and dark"><span class="theme-icon"></span>theme</label>
</header>"#,
        heading = Text(heading),
    )?;
    Ok(())
}

/// One notice: a fact about the scan that changes how the page should be read.
///
/// `alert` is for the ones that make the findings narrower than they look, as
/// against the ones that only say how the document was written.
#[cfg(feature = "export-html")]
pub(crate) fn notice(
    out: &mut dyn Write,
    alert: bool,
    key: &str,
    text: &str,
) -> Result<(), ExportError> {
    let class = if alert {
        "notice notice-alert"
    } else {
        "notice"
    };

    writeln!(
        out,
        "<span class=\"{class}\"><span class=\"notice-key\">{key}</span><span>{text}</span></span>",
        key = Text(key),
        text = Text(text),
    )?;
    Ok(())
}

/// One headline figure. `note` is markup the caller escaped.
#[cfg(feature = "export-html")]
pub(crate) fn tile(
    out: &mut dyn Write,
    value: usize,
    label: &str,
    note: &str,
) -> Result<(), ExportError> {
    writeln!(
        out,
        "<div class=\"tile\"><div class=\"tile-value\">{value}</div><div class=\"tile-label\">{label}</div><div class=\"tile-note\">{note}</div></div>",
        label = Text(label),
    )?;
    Ok(())
}

/// Closes the page container and the document.
#[cfg(feature = "export-html")]
pub(crate) fn foot(out: &mut dyn Write) -> Result<(), ExportError> {
    out.write_all(b"</div>\n</body>\n</html>\n")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// The JSON writers' one shared decision
// ---------------------------------------------------------------------------

/// Sorts a serialization failure into the two cases a caller can act on.
///
/// `serde_json` reports a failed write and an unrepresentable value through the
/// same error type, and they call for opposite responses: retrying against a
/// different destination can fix the first and never the second.
///
/// `format` is the name the caller carries in an
/// [`ExportError::Render`](crate::export::ExportError::Render).
#[cfg(any(feature = "export-json", feature = "export-jsonl"))]
pub(crate) fn render_error(format: &'static str, error: serde_json::Error) -> ExportError {
    if error.is_io() {
        ExportError::Io(error.into())
    } else {
        ExportError::Render {
            format,
            message: error.to_string(),
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

#[cfg(all(test, feature = "export-html"))]
mod tests {
    use super::*;

    /// A device names itself, and what it calls itself is written into a page
    /// somebody opens. This is the security control of the HTML exporters, and
    /// there is one of it.
    #[test]
    fn a_hostname_that_would_execute_is_escaped() {
        let hostile = "<script>alert('pwned')</script>";

        assert_eq!(
            esc(hostile),
            "&lt;script&gt;alert(&#39;pwned&#39;)&lt;/script&gt;"
        );
        assert_eq!(esc("a & b"), "a &amp; b");
        assert_eq!(esc("say \"hi\""), "say &quot;hi&quot;");
    }

    /// A right-to-left override reverses everything after it, so one address can
    /// be made to read as another. It is shown as what it is instead.
    #[test]
    fn direction_and_control_characters_are_shown_rather_than_obeyed() {
        assert_eq!(
            esc("host\u{202e}txt.exe"),
            "host<span class=\"ctl\">U+202E</span>txt.exe"
        );
        assert_eq!(esc("bell\u{7}"), "bell<span class=\"ctl\">U+0007</span>");
        // Whitespace is whitespace, and a script's line breaks are worth having.
        assert_eq!(esc("two\nlines\tapart"), "two\nlines\tapart");
        // A title holds no markup, so the same character degrades instead.
        assert_eq!(Plain("host\u{202e}txt").to_string(), "host\u{fffd}txt");
    }

    /// The two escapers differ in what they put in a neutralized character's
    /// place and in nothing else. A character one of them lets through and the
    /// other does not is the drift that having two of anything here invites.
    #[test]
    fn both_escapers_neutralize_the_same_characters() {
        for code in (0u32..0x2100).chain([0xfeff, 0x1f600]) {
            let Some(character) = char::from_u32(code) else {
                continue;
            };
            let value = character.to_string();

            assert_eq!(
                Text(&value).to_string().contains("class=\"ctl\""),
                Plain(&value).to_string().contains('\u{fffd}'),
                "U+{code:04X} is neutralized by one escaper and not the other"
            );
        }
    }

    /// A title is text, so nothing that reaches one may still be able to open
    /// an element or close the attribute it might one day sit in.
    #[test]
    fn nothing_reaches_a_title_still_carrying_markup() {
        for code in (0u32..0x2100).chain([0xfeff, 0x1f600]) {
            let Some(character) = char::from_u32(code) else {
                continue;
            };
            let plain = Plain(&character.to_string()).to_string();

            for carrier in ['<', '>', '"', '\''] {
                assert!(
                    !plain.contains(carrier),
                    "U+{code:04X} reaches a title as {carrier}"
                );
            }
        }
    }
}
