// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The fields a signature may be written against
//!
//! A signature rule names the `context` it reads, and the matcher runs it
//! against every text a response yields rather than selecting on that name. A
//! rule therefore fires only where this engine produces the field its pattern is
//! anchored on, and [`CONTEXTS`] is the register of which fields those are and
//! what state each is in.
//!
//! Consult it before authoring a signature. A rule reading a field whose
//! [`Reach`] is not [`Produced`](Reach::Produced) never fires, and nothing about
//! the rule shows it: the pattern compiles, its example matches, and no scan
//! hands it the string it was written for.
//!
//! ```
//! use zond_engine::fingerprint::{Reach, reach_of};
//!
//! assert_eq!(reach_of(Some("ssh.banner")), Some(Reach::Produced));
//!
//! // Reachable, but only from inside another field's text.
//! assert_eq!(reach_of(Some("apache_modules")), Some(Reach::Contained));
//!
//! // Nothing this engine scans ever carries it.
//! assert_eq!(reach_of(Some("dhcp_vendor_class")), Some(Reach::OutOfScope));
//!
//! // A rule naming no context is matched against the whole banner.
//! assert_eq!(reach_of(None), Some(Reach::Produced));
//!
//! // A field no entry classifies.
//! assert_eq!(reach_of(Some("something.else")), None);
//! ```
//!
//! `build.rs` reads this file with `#[path]` and refuses to compile a corpus
//! naming a field no entry classifies, so the register and the shipped
//! signatures stay in step. Each entry's `note` names the function responsible,
//! which is what makes a state checkable rather than merely asserted.

/// Whether the collection path produces the field a context names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Reach {
    /// Something in this engine hands the matcher this field. The `note` names
    /// what.
    Produced,

    /// Reached inside a wider field rather than on its own, so a rule fires only
    /// where that wider field happens to carry it. Apache states its module list
    /// and its platform inside the `Server` value.
    Contained,

    /// Nothing produces it, so every rule reading it is inert. The `note` says
    /// what producing it would take.
    Unproduced,

    /// Needs a vantage a scanner does not have, so no decoder would help. A DHCP
    /// vendor class is what a client tells a server, and this engine is neither.
    OutOfScope,
}

impl Reach {
    /// The word this state is reported under, in build output and in an index.
    pub const fn label(self) -> &'static str {
        match self {
            Reach::Produced => "produced",
            Reach::Contained => "contained",
            Reach::Unproduced => "unproduced",
            Reach::OutOfScope => "out-of-scope",
        }
    }

    /// Whether a rule reading a field in this state can fire at all.
    ///
    /// [`Contained`](Self::Contained) counts as reachable: those rules do fire,
    /// on the responses whose wider field carries what they read.
    pub const fn reaches_the_matcher(self) -> bool {
        matches!(self, Reach::Produced | Reach::Contained)
    }
}

/// One field the corpus writes rules against.
#[derive(Debug, Clone, Copy)]
pub struct Context {
    /// The string a rule's `context` states.
    pub name: &'static str,
    /// Whether anything produces it.
    pub reach: Reach,
    /// What produces it, or what producing it would take. Names a function
    /// wherever one is responsible, so the claim can be checked.
    pub note: &'static str,
}

/// Every field the shipped corpus reads, sorted by name.
///
/// A rule stating no context at all is not represented here and needs no entry:
/// it is matched against the banner whole, which every TCP port yields, so it is
/// reached by construction.
pub const CONTEXTS: &[Context] = &[
    Context {
        name: "a2s.info",
        reach: Reach::Produced,
        note: "the strings a Source engine server answers A2S_INFO with, joined on `;` by `framed::source_engine`, or the word `challenge` where the server asked for one instead",
    },
    Context {
        name: "apache_modules",
        reach: Reach::Contained,
        note: "the module list Apache appends to its `Server` value, reached the same way and only when it is present",
    },
    Context {
        name: "apache_os",
        reach: Reach::Contained,
        note: "the platform Apache names inside its own `Server` value, reached through `http::corpus_reading` when the value carries it",
    },
    Context {
        name: "architecture",
        reach: Reach::Produced,
        note: "the instruction set a rule states, collected by `best_match` from every match that named one and filled into whichever operating-system reading won. These seven rules name an architecture and nothing else, so `evidence_from` still declines them as a reading of their own: evidence naming nothing describable cannot stand in a resolver that settles by vote. The most specific match wins, which is what separates `x86_64` from the `x86` rule that matches inside it",
    },
    Context {
        name: "coap.core",
        reach: Reach::Produced,
        note: "the link-format payload served at `/.well-known/core`, read by `framed::coap_payload` after walking the options to the payload marker",
    },
    Context {
        name: "dhcp_vendor_class",
        reach: Reach::OutOfScope,
        note: "what a DHCP client tells a server; this engine is neither, so no decoder reaches it",
    },
    Context {
        name: "dns.versionbind",
        reach: Reach::Produced,
        note: "the TXT answer the `version.bind` probe draws, decoded by `dns::first_text_answer` through `extract::from_datagram`, and through `extract::from_stream` from TCP behind its two-byte length",
    },
    Context {
        name: "favicon.md5",
        reach: Reach::Produced,
        note: "the MD5 of `/favicon.ico`, fetched and hashed by `favicon::FaviconAnalyzer` on a port that already answered in HTTP",
    },
    Context {
        name: "ftp.banner",
        reach: Reach::Produced,
        note: "the greeting, whole, through `extract::texts`",
    },
    Context {
        name: "html_title",
        reach: Reach::Produced,
        note: "the `<title>`, whitespace-normalised, through `http::corpus_fields`",
    },
    Context {
        name: "http_header.cookie",
        reach: Reach::Produced,
        note: "the `Set-Cookie` value, through `http::corpus_fields`",
    },
    Context {
        name: "http_header.server",
        reach: Reach::Produced,
        note: "the `Server` value, through `http::corpus_reading`, which matches it globally rather than through the port index",
    },
    Context {
        name: "http_header.wwwauth",
        reach: Reach::Produced,
        note: "the `WWW-Authenticate` value, through `http::corpus_fields`",
    },
    Context {
        name: "http_header.x-powered-by",
        reach: Reach::Produced,
        note: "the `X-Powered-By` value, through `http::corpus_fields`",
    },
    Context {
        name: "ike.vendor_id",
        reach: Reach::Produced,
        note: "the Vendor ID payloads of an IKE response, as lowercase hex from `framed::ike_response`, or `notify` where the gateway refused the proposal instead of answering it",
    },
    Context {
        name: "imap4.banner",
        reach: Reach::Produced,
        note: "the greeting, whole, through `extract::texts`",
    },
    Context {
        name: "ipmi.auth",
        reach: Reach::Produced,
        note: "the IPMI version and login bits of a Get Channel Authentication Capabilities response, read by `framed::ipmi_auth_capabilities`",
    },
    Context {
        name: "krb.error",
        reach: Reach::Produced,
        note: "the error code, realm and text of a `KRB-ERROR`, read by `framed::kerberos_error`. The realm appears only where it differs from the one the probe invented, since a KDC repeats what it was asked about. Read from TCP as well, behind the four-byte length, by `extract::from_stream`",
    },
    Context {
        name: "l2tp.sccrp",
        reach: Reach::Produced,
        note: "the vendor and host names an L2TP concentrator answers an SCCRQ with, read by `framed::l2tp_control`",
    },
    Context {
        name: "ldap.search_result",
        reach: Reach::Produced,
        note: "the bytes a root DSE search draws, matched as text through `extract::texts`; the corpus probe now asks for the entry at the empty DN as well as binding",
    },
    Context {
        name: "mdns.device-info.txt",
        reach: Reach::Produced,
        note: "the TXT strings a Bonjour responder publishes under the host's own name, asked for by `orchestrator::run_active_os_mdns` and decoded through `extract::from_datagram`",
    },
    Context {
        name: "mdns.workstation.txt",
        reach: Reach::Produced,
        note: "as the device-info record, where a responder publishes one",
    },
    Context {
        name: "mssql.browser",
        reach: Reach::Produced,
        note: "the instance list a SQL Server Browser answers with, read by `framed::sql_server_browser` from behind the three-byte response header",
    },
    Context {
        name: "mysql.banners",
        reach: Reach::Produced,
        note: "the text of the greeting packet, through `extract::texts`",
    },
    Context {
        name: "mysql.error",
        reach: Reach::Produced,
        note: "the error packet a refused handshake returns, read as text the same way",
    },
    Context {
        name: "nntp.banner",
        reach: Reach::Produced,
        note: "the greeting, whole, through `extract::texts`",
    },
    Context {
        name: "ntlm.os_version",
        reach: Reach::Produced,
        note: "the Windows version and build an NTLM challenge states, rendered `Windows 10.0 Build 20348` by `framed::smb2_exchange` from the session setup `smb::SmbAnalyzer` sends over SMB2",
    },
    Context {
        name: "ntp.readvar",
        reach: Reach::Produced,
        note: "the system variables a mode 6 control message draws, read by `framed::ntp_control_variables`. The corpus probe for this port was an ordinary client request, which draws timestamps; the control probe beside it asks the question these rules were written for",
    },
    Context {
        name: "operating_system.name",
        reach: Reach::Produced,
        note: "the `os.product` a first match produced, looked up in these rules alone by `SignatureDb::canonical_os_name` once `best_match` has chosen a winner. Matched against this field's own rules rather than the corpus, because loose banner rules elsewhere read an operating-system name as ordinary text and answer with something coarser than went in",
    },
    Context {
        name: "pop3.banner",
        reach: Reach::Produced,
        note: "the greeting, whole, through `extract::texts`",
    },
    Context {
        name: "raknet.status",
        reach: Reach::Produced,
        note: "the status line a RakNet unconnected pong carries, read by `framed::raknet_pong` once the reply's magic has confirmed it is RakNet",
    },
    Context {
        name: "rpc.program_dump",
        reach: Reach::Produced,
        note: "the programs a portmapper says it has registered, rendered as `name version transport port` by `framed::rpc_program_dump`, from a datagram or from a TCP reply once `framed::rpc_record` has taken its record marks out",
    },
    Context {
        name: "rpc.versions",
        reach: Reach::Produced,
        note: "the version range an RPC server states in a PROG_MISMATCH, read by `framed::rpc_version_range`. The probe calls a version nothing implements so that the mismatch is the answer. Read from TCP as well, once `framed::rpc_record` has taken the record marks out",
    },
    Context {
        name: "rtsp_header.server",
        reach: Reach::Produced,
        note: "the `Server` value of an RTSP response, read by `framed::rtsp_server` through `extract::from_stream`. An RTSP status line is not an HTTP one, so the HTTP reader declines the response and this port has a reader of its own",
    },
    Context {
        name: "sip_header.server",
        reach: Reach::Produced,
        note: "the `Server` value of a SIP response, through `sip::corpus_fields`, drawn by the OPTIONS probe the corpus registers over both transports",
    },
    Context {
        name: "sip_header.user_agent",
        reach: Reach::Produced,
        note: "the `User-Agent` value of the same response; RFC 3261 gives neither header precedence, so both are offered",
    },
    Context {
        name: "smb.native_lm",
        reach: Reach::Produced,
        note: "the LAN manager string of an SMB1 session setup, read by `framed::smb_session_setup` from the exchange `smb::SmbAnalyzer` holds where a server answers in SMB1 or names no Windows build over SMB2",
    },
    Context {
        name: "smb.native_os",
        reach: Reach::Produced,
        note: "the native OS string of the same session setup, and the larger half of the pair",
    },
    Context {
        name: "smb2.negotiate",
        reach: Reach::Produced,
        note: "the dialect and signing policy of an SMB2 negotiate response, rendered by `framed::smb2_exchange` from the exchange `smb::SmbAnalyzer` holds",
    },
    Context {
        name: "smtp.banner",
        reach: Reach::Produced,
        note: "the greeting, whole, through `extract::texts`",
    },
    Context {
        name: "snmp.sys_description",
        reach: Reach::Produced,
        note: "`sysDescr.0`, decoded out of the GetResponse by `extract::from_datagram` for port 161",
    },
    Context {
        name: "snmp.sys_object_id",
        reach: Reach::Produced,
        note: "`sysObjectID.0`, decoded by `snmp::sys_object_id` from the second varbind of the GetRequest already sent, and offered both alone and joined to the description",
    },
    Context {
        name: "ssdp.server",
        reach: Reach::Produced,
        note: "the `SERVER` value of an M-SEARCH answer, read by `http::server_value` and handed back alone by `extract::from_datagram`. A separate field from `http_header.server` because UPnP fixes its grammar: three tokens naming the operating system, the UPnP version and the product, where a web server's is whatever the author felt like writing",
    },
    Context {
        name: "ssh.banner",
        reach: Reach::Produced,
        note: "the software identifier `ssh::software_version` splits out of the identification line, offered beside the whole line by `extract::texts`",
    },
    Context {
        name: "stun.software",
        reach: Reach::Produced,
        note: "the `SOFTWARE` attribute of a STUN binding response, read by `framed::stun_binding`, or `stun` where the server sends none",
    },
    Context {
        name: "tds.prelogin_version",
        reach: Reach::Produced,
        note: "the version a SQL Server states in its pre-login response, rendered `Microsoft SQL Server 15.0.2000` by `framed::tds_version`",
    },
    Context {
        name: "tls.jarm",
        reach: Reach::Produced,
        note: "a JARM hash, computed by `jarm::JarmAnalyzer` from how a TLS port answers ten deliberately awkward hellos and matched by `SignatureDb::identify_jarm` against the rules written for a hash and nothing else. Ten connections, so it is asked only at `ServiceDetection::Thorough` and only where a handshake already succeeded",
    },
    Context {
        name: "unknown",
        reach: Reach::Produced,
        note: "the imported rule stated no field, so it is matched against the banner whole, which every TCP port yields",
    },
    Context {
        name: "wsd.types",
        reach: Reach::Produced,
        note: "the `Types` element of a WS-Discovery ProbeMatches, read by `framed::wsd_types` with the namespace prefixes stripped, since a responder picks its own",
    },
    Context {
        name: "x11.vendor",
        reach: Reach::Produced,
        note: "the vendor string of the connection reply, read as text through `extract::texts`",
    },
    Context {
        name: "x509.issuer",
        reach: Reach::Produced,
        note: "the issuer of the presented chain, rendered and matched as the subject is",
    },
    Context {
        name: "x509.subject",
        reach: Reach::Produced,
        note: "the subject of the presented chain, rendered RFC 4514 by `tls_cert::distinguished_name` and matched by `SignatureDb::identify_field`",
    },
    Context {
        name: "xdmcp.willing",
        reach: Reach::Produced,
        note: "the host and status strings of an XDMCP Willing response, joined by `framed::xdmcp_willing`",
    },
];

/// What the register says about `name`, or [`None`] for a field nobody has
/// classified.
///
/// A linear walk over thirty-six entries. Callers are the build, which runs once,
/// and an index generator, which runs when somebody asks; neither is on a scan's
/// path, so a map would cost more to build than the walk costs to take.
pub fn lookup(name: &str) -> Option<&'static Context> {
    CONTEXTS.iter().find(|context| context.name == name)
}

/// What produces the field `context` names, or what producing it would take.
///
/// [`None`] for a rule naming no context, which needs no explanation, and for a
/// field no entry classifies.
pub fn context_note(context: Option<&str>) -> Option<&'static str> {
    lookup(context?).map(|context| context.note)
}

/// What the collection path does with the field `context` names, where a rule
/// stating no context reads the banner whole and so is always
/// [`Produced`](Reach::Produced).
///
/// [`None`] for a context no entry classifies, which the build refuses.
pub fn reach_of(context: Option<&str>) -> Option<Reach> {
    match context {
        None => Some(Reach::Produced),
        Some(name) => lookup(name).map(|context| context.reach),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two entries for one field would make `lookup` depend on their order, and
    /// the second would be unreachable.
    #[test]
    fn no_field_is_registered_twice() {
        let mut names: Vec<_> = CONTEXTS.iter().map(|c| c.name).collect();
        let before = names.len();
        names.sort_unstable();
        names.dedup();
        assert_eq!(
            names.len(),
            before,
            "a context is registered more than once"
        );
    }

    /// The register is read by hand as often as by the build, and an unsorted
    /// list of thirty-six strings is one nobody checks against the corpus.
    #[test]
    fn the_register_is_sorted_by_name() {
        let names: Vec<_> = CONTEXTS.iter().map(|c| c.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "CONTEXTS is not in name order");
    }

    /// A note is what makes a claim checkable. An entry without one asserts a
    /// state and offers no way to confirm it.
    #[test]
    fn every_entry_says_what_it_rests_on() {
        for context in CONTEXTS {
            assert!(
                !context.note.trim().is_empty(),
                "{} states no note",
                context.name
            );
        }
    }

    #[test]
    fn a_rule_stating_no_context_reads_the_banner_and_is_reached() {
        assert_eq!(reach_of(None), Some(Reach::Produced));
    }

    #[test]
    fn an_unclassified_field_is_refused_rather_than_assumed_reachable() {
        assert_eq!(reach_of(Some("nothing.classifies.this")), None);
    }

    #[test]
    fn a_contained_field_counts_as_reaching_the_matcher() {
        assert!(Reach::Contained.reaches_the_matcher());
        assert!(Reach::Produced.reaches_the_matcher());
        assert!(!Reach::Unproduced.reaches_the_matcher());
        assert!(!Reach::OutOfScope.reaches_the_matcher());
    }
}
