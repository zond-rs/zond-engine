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
//! assert_eq!(reach_of(Some("favicon.md5")), Some(Reach::Unproduced));
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
        name: "apache_modules",
        reach: Reach::Contained,
        note: "the module list Apache appends to its `Server` value, reached the same way and only when it is present",
    },
    Context {
        name: "apache_os",
        reach: Reach::Contained,
        note: "the platform Apache names inside its own `Server` value, reached through `http::os_from` when the value carries it",
    },
    Context {
        name: "architecture",
        reach: Reach::Unproduced,
        note: "nothing, and the blocker is not the text: these patterns are unanchored and match a `uname` banner already. They state only `os.arch`, which `OsMetadata` has no field for and which makes `from_map` drop the rule for naming neither a family nor a product",
    },
    Context {
        name: "dhcp_vendor_class",
        reach: Reach::OutOfScope,
        note: "what a DHCP client tells a server; this engine is neither, so no decoder reaches it",
    },
    Context {
        name: "dns.versionbind",
        reach: Reach::Produced,
        note: "the TXT answer the `version.bind` probe draws, decoded by `dns::first_text_answer` through `extract::from_datagram`",
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
        note: "the `Server` value, through `http::os_from`, which matches it globally rather than through the port index",
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
        name: "imap4.banner",
        reach: Reach::Produced,
        note: "the greeting, whole, through `extract::texts`",
    },
    Context {
        name: "ldap.search_result",
        reach: Reach::Unproduced,
        note: "a root DSE search result; the corpus probe is an anonymous bind and draws no entry",
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
        name: "ntp.readvar",
        reach: Reach::Unproduced,
        note: "a mode-6 control response; the corpus probe is an ordinary client request and draws a timestamp instead",
    },
    Context {
        name: "operating_system.name",
        reach: Reach::Unproduced,
        note: "a second matching stage: the `os.product` an earlier match produced, fed back through the corpus. The text reaches the matcher only when a reply happens to be a bare operating-system name",
    },
    Context {
        name: "pop3.banner",
        reach: Reach::Produced,
        note: "the greeting, whole, through `extract::texts`",
    },
    Context {
        name: "rtsp_header.server",
        reach: Reach::Unproduced,
        note: "the `Server` value of an RTSP response; wants an OPTIONS probe",
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
        reach: Reach::Unproduced,
        note: "the LAN manager string of a session setup; the corpus probe stops at a protocol negotiate",
    },
    Context {
        name: "smb.native_os",
        reach: Reach::Unproduced,
        note: "the native OS string of a session setup; as above, and the larger half of the pair",
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
        name: "ssh.banner",
        reach: Reach::Produced,
        note: "the software identifier `ssh::software_version` splits out of the identification line, offered beside the whole line by `extract::texts`",
    },
    Context {
        name: "tls.jarm",
        reach: Reach::Unproduced,
        note: "a JARM hash; wants the probe sequence and the digest, neither of which this engine computes",
    },
    Context {
        name: "unknown",
        reach: Reach::Produced,
        note: "the imported rule stated no field, so it is matched against the banner whole, which every TCP port yields",
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
