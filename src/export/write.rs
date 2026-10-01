// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Shared writing helpers
//!
//! Pieces more than one format needs: the escaper every page puts report text
//! through, the scaffolding shared by the report and comparison pages, and the
//! mapping from a `serde_json` failure onto [`ExportError`].
//!
//! Only pieces with one right spelling belong here; each format keeps its own
//! markup, order and vocabulary. Keeping one escaper means a fix to it reaches
//! every page.
//!
//! Every item is gated by exactly the formats that call it, so `export-csv`
//! does not compile a stylesheet nor `export-html` compile `serde_json`.
//! `cargo hack check --each-feature` checks the gates.

#[cfg(feature = "export-html")]
use std::fmt::{self, Write as _};
#[cfg(feature = "export-html")]
use std::io::Write;

use crate::export::ExportError;
#[cfg(feature = "export-html")]
use crate::export::schema::ENGINE_NAME;

// ---------------------------------------------------------------------------
// Escaping
// ---------------------------------------------------------------------------

/// Report text, escaped for a page as it is written.
///
/// Everything a scanned network chose to call itself passes through here.
/// Besides the five markup characters, bidirectional formatting and control
/// characters are rendered as their code points (see `is_neutralized`).
///
/// This writes markup, so it belongs in element content only. No writer in this
/// crate puts a report value into an attribute.
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
/// For a document's title, where a `<span>` would render as its own source. A
/// neutralized character becomes U+FFFD.
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

/// Whether a character is shown as its code point.
///
/// Bidirectional formatting characters invisibly reorder the text around them,
/// so a hostname could make a report display one thing and mean another.
/// Control characters render as nothing, so a banner would silently lose them.
///
/// Tab, newline and carriage return pass through, keeping the shape of a
/// script's multi-line output.
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
// Stylesheet and tone classes
// ---------------------------------------------------------------------------

/// The stylesheet inlined into every page this crate writes.
///
/// A test pins the class names it defines to the ones the report page writes.
#[cfg(feature = "export-html")]
pub(crate) const STYLE: &str = include_str!("../../assets/html/report.css");

/// Something is there and answering: `up`, `open`, a host that appeared.
///
/// One of four tones. The state's name is always printed beside its colour, so
/// the colour says how much the finding is worth a second look.
#[cfg(feature = "export-html")]
pub(crate) const TONE_FOUND: &str = "s-found";

/// Something is there and the scan could not pin it down. Drawn hatched as well
/// as coloured, since green against amber is lost to colour-blind readers and
/// in greyscale print.
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
/// The `generator` meta tag names this build. Who produced the findings goes
/// in each page's own colophon.
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
/// `subtitle` is markup the caller escaped.
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
/// `alert` marks a notice that makes the findings narrower than they look;
/// without it, a notice only says how the document was written.
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
// JSON errors
// ---------------------------------------------------------------------------

/// Sorts a serialization failure into the two cases a caller can act on.
///
/// `serde_json` reports a failed write and an unrepresentable value through the
/// same error type; only the first can be fixed by retrying elsewhere.
///
/// `format` is the name the caller carries in an
/// [`ExportError::Render`].
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

    /// A device's self-chosen name is written into a page somebody opens. This
    /// is the HTML exporters' one escaping control.
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

    /// A right-to-left override can make one address read as another, so it is
    /// shown as a code point.
    #[test]
    fn direction_and_control_characters_are_shown_rather_than_obeyed() {
        assert_eq!(
            esc("host\u{202e}txt.exe"),
            "host<span class=\"ctl\">U+202E</span>txt.exe"
        );
        assert_eq!(esc("bell\u{7}"), "bell<span class=\"ctl\">U+0007</span>");
        // Whitespace passes through.
        assert_eq!(esc("two\nlines\tapart"), "two\nlines\tapart");
        // A title holds no markup, so the character becomes U+FFFD.
        assert_eq!(Plain("host\u{202e}txt").to_string(), "host\u{fffd}txt");
    }

    /// The two escapers differ only in what replaces a neutralized character.
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

    /// Nothing reaching a title can open an element or close an attribute.
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
