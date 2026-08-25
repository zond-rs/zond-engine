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
//! since this engine's nmap exporter writes the same format - becomes the
//! target list for the next one, hosts and per-host ports together.
//!
//! ## The refusals are the security control
//!
//! The parsing is `xml`'s, and so are the refusals that make
//! reading a file somebody else wrote defensible: no declaration of any kind is
//! accepted, so no entity can be expanded or fetched, and depth, element count,
//! name length and attribute length are all bounded. That module is where the
//! whole argument lives.
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
//! Reading the same document for what the scan *found* rather than for what to
//! scan next is [`report::nmap`](super::report::nmap), which shares this
//! module's parser and keeps a much longer list of attributes.
//!
//! A hardware address is skipped: a MAC is not something to scan. Hostnames are
//! skipped too, because every nmap host record carries an address and resolving
//! a name again would be work with a worse answer.
//!
//! Ports are not filtered by state, for the same reason the JSON reader does not
//! filter: the file is the caller's own selection, and "rescan what nmap found"
//! should not quietly mean "rescan some of it".

use std::io::BufRead;

use crate::import::xml::{Element, Event, Parser};
use crate::import::{ImportError, ImportLimits, Importer, Origin, TargetSink};

/// The format's name in errors.
const FORMAT: &str = "nmap XML";

/// The attributes worth keeping. Everything else is skipped unbuffered.
///
/// Four, because reading a document as targets needs an address and a port and
/// nothing else. The reader that takes the same document as *findings* names a
/// much longer list; see [`report::nmap`](crate::import::report::nmap).
const KEPT: &[&[u8]] = &[b"addr", b"addrtype", b"protocol", b"portid"];

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
        let mut parser = Parser::new(input, self.limits.max_line_bytes, FORMAT, KEPT);
        let mut host: Option<Accumulator> = None;
        let mut saw_root = false;
        let mut token = String::new();

        loop {
            match parser.next_event()? {
                Event::Eof => break,

                Event::Start { self_closing } => {
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
            "<a>".repeat(crate::import::xml::MAX_DEPTH + 8),
            "</a>".repeat(crate::import::xml::MAX_DEPTH + 8)
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
