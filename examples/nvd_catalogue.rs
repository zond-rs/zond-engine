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
//! Run from the crate root. A path ending in `.xz` is piped through `xz -dc`
//! (on the `PATH`), so the several hundred megabytes per year never touch disk.
//! Pass the years in order; the output keeps it, and a regeneration is reviewed
//! as a diff.
//!
//! ## Why a year at a time
//!
//! A converted document is capped at
//! [`MAX_DOCUMENT_BYTES`](zond_engine::cve::MAX_DOCUMENT_BYTES), and the whole
//! history exceeds it. The shipped file is compiled by `build.rs`, which has no
//! cap, so it holds every year.
//!
//! Entries are filtered by the shipped fingerprint corpus
//! (`import::nvd::to_document`), so a product gains rows once the corpus
//! versions it and the catalogue is regenerated.

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
# A vulnerability NVD states only for one platform, *running on* Windows, one
# distribution or one appliance, is left out: an entry is judged against one
# service's CPE and the condition has nowhere to go.
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

        // The years share one timestamp; should they differ, the newest is used.
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
