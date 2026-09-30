// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Regenerating the shipped list of exploited vulnerabilities
//!
//! Produces `assets/cve/kev.toml` from the JSON CISA publishes, converted
//! through `import::kev::exploited` and written under the header the shipped
//! file carries.
//!
//! ```text
//! curl -sSfLO https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
//! cargo run --example kev_list --features import-kev -- \
//!     known_exploited_vulnerabilities.json > assets/cve/kev.toml
//! ```
//!
//! Run from the crate root, before a release: a scan marks findings by this
//! list unless it is handed a newer one.

use std::fs::File;
use std::io::{BufReader, Write};

use zond_engine::import::kev;

/// What the shipped file says about itself, above the list.
const HEADER: &str = "\
# Vulnerabilities known to be exploited in the wild, by CVE identifier.
#
# GENERATED. Do not edit by hand: `zond_engine::import::kev::exploited`
# converts the feed and the `kev_list` example writes this.
#
# ## Where the data comes from
#
# CISA's Known Exploited Vulnerabilities catalogue,
# https://www.cisa.gov/known-exploited-vulnerabilities-catalog, dedicated to
# the public domain under CC0 1.0 (https://github.com/cisagov/kev-data). Only
# the identifiers are kept: a correlation marks the findings that cite them.

";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: kev_list <known_exploited_vulnerabilities.json>")?;
    let list = kev::exploited(&mut BufReader::new(File::open(path)?))?;
    let mut out = std::io::stdout().lock();
    out.write_all(HEADER.as_bytes())?;
    out.write_all(list.to_document().as_bytes())?;
    eprintln!("{} {}: {} CVEs", list.id(), list.version(), list.len());
    Ok(())
}
