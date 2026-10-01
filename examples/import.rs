// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Getting targets into the engine
//!
//! Everything the `import` module can read, in the order it is likely to be
//! needed. Needs no privileges or network: every document is a string in this
//! file, read through the same path a real file takes.
//!
//! ```text
//! cargo run --example import                     # the list format
//! cargo run --example import --features import-all   # every format
//! ```
//!
//! ## Readers, not paths
//!
//! An importer reads from a `BufRead`. The engine opens no files and reads no
//! standard input; the caller hands it a reader:
//!
//! ```no_run
//! # use std::io::BufReader;
//! # use std::fs::File;
//! # fn main() -> std::io::Result<()> {
//! let mut file = BufReader::new(File::open("targets.txt")?);       // a file
//! let mut piped = std::io::stdin().lock();                          // a pipe
//! let mut uploaded = std::io::Cursor::new(b"192.0.2.1".to_vec()); // a body
//! # Ok(())
//! # }
//! ```
//!
//! All three parse identically, so the same code serves a CLI, a web service or
//! a TUI.

use std::io::Cursor;

use zond_engine::import::{ImportFormat, ImportLimits, ImportOptions, OnRefusal};
use zond_engine::model::port::PortSet;

fn main() {
    heading("1. A list of addresses");
    a_list_of_addresses();

    heading("2. Ports per target");
    ports_per_target();

    heading("3. Feeding discovery and feeding a port scan");
    both_entry_points();

    heading("4. One bad line out of five thousand");
    surviving_a_bad_line();

    heading("5. Bounding input you did not write");
    bounding_untrusted_input();

    heading("6. Letting the engine work out the format");
    working_out_the_format();

    heading("7. Rescanning what a previous scan found");
    rescanning_a_report();

    heading("8. Reading an nmap file");
    reading_an_nmap_file();

    heading("9. Settings and named profiles");
    settings_and_profiles();
}

/// The common case: one target per line, `#` starting a comment.
///
/// Blank lines, comments, indentation, both line endings and a byte-order mark
/// are skipped. A line too long, or bytes that are not UTF-8, are errors naming
/// the line.
fn a_list_of_addresses() {
    let file = "\
# staging, 2026-02
192.0.2.1
192.0.2.20
192.0.2.53

# the whole management block
198.51.100.0/28
203.0.113.1-203.0.113.5
";

    // The ports a target that names none is scanned on.
    let options = ImportOptions::new(ports("22,443"));

    let imported = ImportFormat::List
        .read(&mut Cursor::new(file), &options)
        .expect("the list is well formed");

    println!("read {} expressions", imported.tokens);
    println!("covering {} addresses", imported.addresses);
    println!("as {} unit(s) of work", imported.map.units.len());
}

/// A target can carry its own ports, and the grammar is the same one a command
/// line uses.
///
/// A bare address with two or more colons is an address, never an address and a
/// port: `2001:db8::1:80` is an IPv6 address. Write `[2001:db8::1]:80` for a port.
fn ports_per_target() {
    let file = "\
192.0.2.1:22,443            # two TCP ports
192.0.2.2:1-1024            # a range
192.0.2.3:u:53,u:161        # UDP, with the u: prefix
198.51.100.0/29:8080        # every address in the block, one port
[2001:db8::1]:443           # IPv6 needs brackets to carry ports
2001:db8::2                 # ...and without them it is just an address
";

    let options = ImportOptions::new(ports("80"));
    let imported = ImportFormat::List
        .read(&mut Cursor::new(file), &options)
        .expect("the list is well formed");

    // One unit per distinct port specification, however many lines share it.
    println!("{} distinct port specifications:", imported.map.units.len());
    for unit in &imported.map.units {
        println!(
            "  {:>3} address(es) on {}",
            unit.ips().len(),
            describe(unit.ports())
        );
    }
}

/// The engine has two entry points and they take different things.
///
/// - [`zond_engine::scanner::scan`] takes the `TargetMap` as it stands: it asks
///   which of these ports are open on which of these hosts.
/// - [`zond_engine::scanner::discover`] takes an `IpSet`: it asks only whether a
///   host is there at all, so it has no use for ports.
///
/// `into_ip_set` bridges them: a host under two port specifications is two units
/// to scan and one host to sweep.
fn both_entry_points() {
    let file = "192.0.2.1:22\n192.0.2.1:443\n192.0.2.2:22\n";
    let options = ImportOptions::new(ports("80"));

    let imported = ImportFormat::List
        .read(&mut Cursor::new(file), &options)
        .expect("the list is well formed");

    println!("to port-scan: {} units", imported.map.units.len());
    println!(
        "             {} probes",
        imported.map.clone().gross_targets().unwrap()
    );

    let sweep = imported.into_ip_set();
    println!("to discover:  {} hosts", sweep.len());

    println!();
    println!(
        "    let (session, task) = scanner::scan(imported.map, &config, Detections::embedded()).await?;"
    );
    println!("    let (session, task) = scanner::discover(sweep, &config).await?;");
}

/// A five-thousand-line target list with one typo in it.
///
/// By default import stops at the first bad expression and names its line.
///
/// [`OnRefusal::Collect`] keeps the other 4,999 lines and hands the refusals back.
/// There is no option that drops them silently.
fn surviving_a_bad_line() {
    let file = "\
192.0.2.1
192.0.2.300
192.0.2.2
not-a-host-or-an-address
192.0.2.3
";

    // The default: stop and say where.
    let strict = ImportOptions::new(ports("80"));
    match ImportFormat::List.read(&mut Cursor::new(file), &strict) {
        Ok(_) => unreachable!(),
        Err(error) => println!("default (Abort): {error}"),
    }

    // Carry on, and report.
    let lenient = ImportOptions::new(ports("80")).with_refusal_policy(OnRefusal::Collect);
    let imported = ImportFormat::List
        .read(&mut Cursor::new(file), &lenient)
        .expect("collecting does not fail the import");

    println!(
        "collected: {} addresses scannable, {} refused",
        imported.addresses,
        imported.refusals.len()
    );
    for refusal in &imported.refusals {
        println!("  {refusal}");
    }
}

/// A target file from a client is input nobody vouches for.
///
/// [`ImportLimits`] is part of the options, and every default is far past what an
/// honest file reaches. The important one is `max_addresses`, defaulting to 2^32
/// (all of IPv4), since `::/0` is one short line naming more addresses than any
/// scan finishes.
fn bounding_untrusted_input() {
    let options = ImportOptions::new(ports("80"));

    match ImportFormat::List.read(&mut Cursor::new("::/0\n"), &options) {
        Ok(_) => unreachable!(),
        Err(error) => println!("refused: {error}"),
    }

    // The whole of IPv4 is inside the default ceiling.
    let imported = ImportFormat::List
        .read(&mut Cursor::new("0.0.0.0/0\n"), &options)
        .expect("the whole of IPv4 is a scan");
    println!("accepted: {} addresses", imported.addresses);

    // Tighten it for a context where even that is too much...
    let tight = ImportOptions::new(ports("80"))
        .with_limits(ImportLimits::default().with_max_addresses(4096));
    match ImportFormat::List.read(&mut Cursor::new("10.0.0.0/8\n"), &tight) {
        Ok(_) => unreachable!(),
        Err(error) => println!("tightened: {error}"),
    }

    // ...or lift it entirely for input the caller wrote itself.
    let trusted = ImportOptions::new(ports("80")).with_limits(ImportLimits::none());
    let imported = ImportFormat::List
        .read(&mut Cursor::new("::/0\n"), &trusted)
        .expect("limits lifted");
    println!("lifted: {} addresses", imported.addresses);
}

/// Two ways to know what is being read, and one refusal to guess.
///
/// `from_path` reads the extension: a name is something the caller was told.
/// `sniff` reads the first bytes without consuming them, for input that arrived
/// down a pipe with no name at all. `resolve` does the first and falls back to
/// the second.
///
/// Sniffing only separates structured documents from lists; anything ambiguous is
/// a list. A leading `[` is not JSON (`[2001:db8::1]:443`), and a comma is not CSV
/// (`192.0.2.1,192.0.2.2`).
fn working_out_the_format() {
    for (name, document) in [
        ("a plain list", "192.0.2.1\n192.0.2.2\n"),
        ("a bracketed IPv6 target", "[2001:db8::1]:443\n"),
        ("comma-separated addresses", "192.0.2.1,192.0.2.2\n"),
        ("something XML-shaped", "<?xml version=\"1.0\"?><nmaprun/>"),
        ("something JSON-shaped", "{\"schema_version\":1}"),
    ] {
        let mut input = Cursor::new(document);
        let format = ImportFormat::sniff(&mut input).expect("sniffing does not consume");
        println!("{name:>26} -> {format}");
    }

    println!();
    println!("formats this build can read: {:?}", ImportFormat::all());
}

/// Scan, export, feed the report back in: the same hosts, on the ports they
/// were found on.
///
/// Reads both the JSON document and the record-per-line form. A host with no
/// ports comes back on the caller's default ports, so a discovery sweep can be
/// re-imported.
#[cfg(feature = "import-json")]
fn rescanning_a_report() {
    // What `zond_engine::export::json` writes, cut to the fields a rescan reads.
    let report = r#"{
        "schema_version": 1,
        "engine": { "name": "zond-engine", "version": "0.10.0" },
        "hosts": [
            { "primary_ip": "192.0.2.1",
              "ips": ["192.0.2.1"],
              "ports": [ { "port": 22, "protocol": "tcp", "state": "open" },
                         { "port": 53, "protocol": "udp", "state": "open" } ] },
            { "primary_ip": "192.0.2.9", "ips": ["192.0.2.9"], "ports": [] }
        ]
    }"#;

    let options = ImportOptions::new(ports("80"));
    let imported = ImportFormat::Json
        .read(&mut Cursor::new(report), &options)
        .expect("a report this engine wrote reads back");

    println!(
        "{} {} to recheck:",
        imported.addresses,
        if imported.addresses == 1 {
            "host"
        } else {
            "hosts"
        }
    );
    for unit in &imported.map.units {
        println!("  {} on {}", unit.ips().len(), describe(unit.ports()));
    }
    println!("(the host with no ports fell back to the default, 80/tcp)");
}

#[cfg(not(feature = "import-json"))]
fn rescanning_a_report() {
    skipped("import-json");
}

/// The file somebody already has.
///
/// nmap XML from a previous engagement becomes the next target list, hosts and
/// per-host ports together. This engine writes the same format.
///
/// The parser accepts nmap's preamble (XML declaration, bare
/// `<!DOCTYPE nmaprun>`, stylesheet instruction) and refuses entity declarations,
/// DOCTYPEs with an internal subset or external identifier, and entity references
/// other than the five predefined. Billion laughs and external entity disclosure
/// are unrepresentable.
#[cfg(feature = "import-nmap")]
fn reading_an_nmap_file() {
    let document = concat!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n",
        "<!DOCTYPE nmaprun>\n",
        "<?xml-stylesheet href=\"file:///usr/share/nmap/nmap.xsl\" type=\"text/xsl\"?>\n",
        "<nmaprun scanner=\"nmap\" version=\"7.99\" xmloutputversion=\"1.05\">\n",
        "<host><status state=\"up\" reason=\"echo-reply\"/>\n",
        "<address addr=\"192.0.2.1\" addrtype=\"ipv4\"/>\n",
        "<address addr=\"aa:bb:cc:dd:ee:ff\" addrtype=\"mac\" vendor=\"Arris\"/>\n",
        "<ports><port protocol=\"tcp\" portid=\"22\"><state state=\"open\"/></port>\n",
        "<port protocol=\"tcp\" portid=\"80\"><state state=\"open\"/></port></ports>\n",
        "</host></nmaprun>\n",
    );

    let options = ImportOptions::new(ports("443"));
    let imported = ImportFormat::NmapXml
        .read(&mut Cursor::new(document), &options)
        .expect("a real nmap document reads");

    println!(
        "{} {} from nmap's output",
        imported.addresses,
        if imported.addresses == 1 {
            "host"
        } else {
            "hosts"
        }
    );
    println!("(the hardware address is not a target and was skipped)");

    // And what a hostile document gets.
    let hostile = concat!(
        "<!DOCTYPE nmaprun [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>",
        "<nmaprun><host><address addr=\"&xxe;\" addrtype=\"ipv4\"/></host></nmaprun>",
    );
    match ImportFormat::NmapXml.read(&mut Cursor::new(hostile), &options) {
        Ok(_) => unreachable!(),
        Err(error) => println!("refused: {error}"),
    }
}

#[cfg(not(feature = "import-nmap"))]
fn reading_an_nmap_file() {
    skipped("import-nmap");
}

/// Defaults a user sets once, and named profiles to switch between.
///
/// Everything here can also be done by setting `ZondConfig` fields directly.
///
/// Nothing touches the filesystem unless asked. `paths::user()` only computes a
/// path, `provision` creates a file only where none exists, and `resolve` reads
/// existing files. No scanner calls any of them, so an embedding service is not
/// affected by files in a home directory.
#[cfg(feature = "import-settings")]
fn settings_and_profiles() {
    use zond_engine::config::ZondConfig;
    use zond_engine::import::settings;

    let document = r#"
        [defaults]
        effort = "balanced"
        max_probe_rate = 20000

        [profiles.stealth]
        tcp_technique = "fin"
        max_probe_rate = 200
        no_dns = true
    "#;

    let loaded = settings::parse(document).expect("the document is well formed");

    // A profile overrides only the keys it mentions.
    let stealth = loaded
        .document
        .resolve(Some("stealth"))
        .expect("the profile exists");

    let mut config = ZondConfig::default();
    stealth.apply_to(&mut config);

    println!("under [profiles.stealth]:");
    println!("  technique     {}", config.tcp_technique);
    println!("  rate          {:?}", config.max_probe_rate);
    println!(
        "  effort        {} (inherited from [defaults])",
        config.retry.effort
    );
    println!("  no_dns        {}", config.no_dns);

    // An undefined profile is an error listing the ones that exist.
    match loaded.document.resolve(Some("quiet")) {
        Ok(_) => unreachable!(),
        Err(error) => println!("\n{error}"),
    }

    // Where the file would live on this machine. Computed, not opened.
    match settings::paths::user() {
        Some(path) => println!("\na settings file would live at {}", path.display()),
        None => println!("\nthis environment names no home directory"),
    }
    println!("call settings::provision_user() to create one if there is none");
}

#[cfg(not(feature = "import-settings"))]
fn settings_and_profiles() {
    skipped("import-settings");
}

// ---------------------------------------------------------------------------
// Small helpers, so the demonstrations above stay about the library
// ---------------------------------------------------------------------------

fn ports(specification: &str) -> PortSet {
    PortSet::try_from(specification).expect("the port specification is well formed")
}

/// A port set in a line, however many ports it holds.
///
/// `PortSet::iter` yields every port, too many to print for `1-1024`.
fn describe(set: &PortSet) -> String {
    const SHOWN: usize = 4;

    let listed: Vec<String> = set
        .iter()
        .take(SHOWN)
        .map(|(port, protocol)| format!("{port}/{protocol:?}").to_lowercase())
        .collect();

    match set.len().saturating_sub(SHOWN) {
        0 => listed.join(", "),
        rest => format!("{} and {rest} more", listed.join(", ")),
    }
}

fn heading(title: &str) {
    println!("\n\x1b[1m{title}\x1b[0m");
    println!("{}", "-".repeat(title.len()));
}

#[allow(dead_code)]
fn skipped(feature: &str) {
    println!("(not built: re-run with --features {feature})");
}
