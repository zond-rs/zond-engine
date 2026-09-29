// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Regenerating the shipped vulnerability catalogue
//!
//! Produces `assets/cve/nvd.toml` from the year files of the community
//! reconstruction of the NVD feed, one `CVE-<year>.json` per year, each
//! converted through `import::nvd` and concatenated under the header the
//! shipped file carries.
//!
//! ```text
//! cargo run --example nvd_catalogue --features import-nvd -- \
//!     feeds/CVE-*.json.xz > assets/cve/nvd.toml
//! ```
//!
//! Run from the crate root. A path ending in `.xz` is read through `xz -dc`,
//! which has to be on the `PATH`: a year of the feed is several hundred
//! megabytes decompressed, and piping it means none of that is written to disk.
//! Pass the years in order, since the output keeps the order it was given and
//! a regeneration is reviewed as a diff against the last one.
//!
//! ## Why a year at a time
//!
//! A converted document is capped at the catalogue reader's
//! [`MAX_DOCUMENT_BYTES`](zond_engine::cve::MAX_DOCUMENT_BYTES), and the whole
//! history converts to more than that. The shipped file is compiled by
//! `build.rs` rather than read through that cap, so it can hold every year; a
//! single conversion cannot, and `import::nvd` says so rather than truncating.
//!
//! The filter is the shipped fingerprint corpus, as `import::nvd::to_document`
//! applies it, so a regeneration after the corpus learns to version a product
//! is what gives that product its rows.

use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use zond_engine::import::nvd;

/// What the shipped file says about itself, above the entries.
const HEADER: &str = "\
# Known vulnerabilities, keyed by the CPE a service identification produces.
#
# GENERATED. Do not edit by hand: `zond_engine::import::nvd` converts the feed
# and this is its output, concatenated one year at a time by the `nvd_catalogue`
# example. Corrections go in `seed.toml` beside it, which is hand-written and
# read alongside this.
#
# ## Where the data comes from
#
# The National Vulnerability Database, whose records are a work of the United
# States government and are in the public domain under 17 U.S.C. 105. The CVE
# identifiers, descriptions and references within them are CVE(R) content,
# reproduced under the CVE Program's terms of use.
#
#   CVE(R) is a registered trademark of The MITRE Corporation.
#   CVE content is copyright The MITRE Corporation, used under the perpetual,
#   worldwide, royalty-free licence the CVE Program grants for reproduction and
#   distribution: https://www.cve.org/Legal/TermsOfUse
#
# Neither NIST nor MITRE endorses this software or its use of their data.
#
# ## What is here and what is not
#
# Only entries naming software this engine's fingerprint corpus can identify
# *with a version*, which is a small fraction of the feed: an entry for software
# no scan can put a version to has nothing to match against. Applications only —
# an operating-system CPE's version is a release family rather than anything a
# banner states, so a CVE keyed to one would fire on every host of that family
# and could be neither confirmed nor denied.
#
# A vulnerability with disjoint version ranges appears once per range, because
# `affected` is a conjunction and cannot say \"or\".
";

/// Where a converted document's entries begin, after its `id` and `version`.
const FIRST_ENTRY: &str = "[[vulnerability]]\n";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<String> = std::env::args().skip(1).collect();
    if paths.is_empty() {
        return Err("usage: nvd_catalogue CVE-<year>.json[.xz]...".into());
    }

    let mut version = String::new();
    let mut entries = String::new();
    for path in &paths {
        let document = convert(path)?;

        // Every year of one release carries the same timestamp, and the newest
        // is the honest one to put on the whole should they ever differ.
        let stated = document
            .lines()
            .find_map(|line| line.strip_prefix("version = "))
            .ok_or_else(|| format!("{path}: the converted document names no version"))?
            .trim_matches('"')
            .to_string();
        if newer(&stated, &version) {
            version = stated;
        }

        if let Some(start) = document.find(FIRST_ENTRY) {
            entries.push_str(document[start..].trim_end());
            entries.push_str("\n\n");
        }
        eprintln!("{path}: converted");
    }

    let mut out = std::io::stdout().lock();
    write!(
        out,
        "{HEADER}\nid = \"{}\"\nversion = \"{version}\"\n\n{}",
        nvd::NVD_ID,
        entries.trim_end()
    )?;
    writeln!(out)?;
    Ok(())
}

/// One year of the feed, converted.
fn convert(path: &str) -> Result<String, Box<dyn std::error::Error>> {
    if !path.ends_with(".xz") {
        let mut input = BufReader::new(File::open(path)?);
        return Ok(nvd::to_document(&mut input)?);
    }

    let mut child = Command::new("xz")
        .args(["-dc", path])
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|error| format!("{path}: xz could not be run: {error}"))?;
    let stdout = child.stdout.take().ok_or("xz gave no output")?;
    let mut input: Box<dyn BufRead> = Box::new(BufReader::new(stdout));
    let document = nvd::to_document(&mut input);
    drop(input);

    let status = child.wait()?;
    if !status.success() {
        return Err(format!("{path}: xz failed: {status}").into());
    }
    Ok(document?)
}

/// Whether the `major.minor.patch` in `a` is later than the one in `b`, where
/// an empty `b` is earlier than anything.
fn newer(a: &str, b: &str) -> bool {
    let parse = |value: &str| -> Vec<u32> {
        value
            .split('.')
            .map(|part| part.parse().unwrap_or(0))
            .collect()
    };
    parse(a) > parse(b)
}
