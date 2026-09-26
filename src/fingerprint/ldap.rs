// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # LDAP root DSE analyzer
//!
//! A **passive** analyzer for the root entry of an LDAP directory, which the
//! corpus's probe for the port asks for and which RFC 4512 §5.1 makes readable
//! without credentials. The corpus matches the answer as text, and names the
//! directory and the release of the controller that serves it. What it cannot
//! do is lift a value out, and three of the entry's values are the names a
//! domain controller goes by:
//!
//! | attribute | kind |
//! |---|---|
//! | `dnsHostName` | [`Host`](NameKind::Host), the controller's DNS name |
//! | `defaultNamingContext` | [`Domain`](NameKind::Domain), the domain it serves |
//! | `rootDomainNamingContext` | [`Forest`](NameKind::Forest), the forest's root domain |
//!
//! The two naming contexts are distinguished names, `DC=corp,DC=example`, and
//! Active Directory names a domain's partition after the domain's DNS name one
//! label per component, so each is read back into the DNS name it spells. A
//! context written with any other component is a directory that does not name
//! its partitions that way, OpenLDAP's `o=example` among them, and says nothing
//! about a domain.
//!
//! These are recorded on the host as [`HostName`]s rather than matched, for
//! the reason [`name`](crate::model::host::name) gives: a report masks a name,
//! and does not mask a service's description.
//!
//! ## Passive, by design
//!
//! The entry is already in the responses the probe drew, so asking again would
//! double the traffic to every directory for an answer already read. What that
//! costs is reading the entry back out of text: see
//! [`reply_bytes`](super::extract::reply_bytes) for how exact that is.

use async_trait::async_trait;

use super::analyzer::{Analyzer, PortContext};
use super::model::{Evidence, SourceId};
use super::response::{Collected, ResponseSet};
use crate::model::confidence::Confidence;
use crate::model::host::{HostName, NameKind, NameSource};

/// BER's tag for a SEQUENCE, which an LDAPMessage and each attribute are.
const SEQUENCE: u8 = 0x30;

/// BER's tag for a SET, which an attribute's values are.
const SET: u8 = 0x31;

/// BER's tag for an OCTET STRING, which a name and a value are.
const OCTET_STRING: u8 = 0x04;

/// BER's tag for an INTEGER, which a message ID is.
const INTEGER: u8 = 0x02;

/// A SearchResultEntry, `[APPLICATION 4]` constructed (RFC 4511 §4.5.2).
const SEARCH_RESULT_ENTRY: u8 = 0x64;

/// Reads the names a directory's root entry gives for the controller serving
/// it. See the module docs.
pub(crate) struct LdapAnalyzer;

#[async_trait]
impl Analyzer for LdapAnalyzer {
    fn id(&self) -> SourceId {
        SourceId::Ldap
    }

    /// Any TCP port, since a directory on an unusual one answers the same
    /// entry; `analyze` gates on the reply itself.
    fn interested(&self, ctx: &PortContext) -> bool {
        ctx.protocol == crate::model::port::Protocol::Tcp
    }

    // Passive, so the default no-op `collect` stands. See the module docs.

    /// The names in the first root entry among the responses, as one
    /// observation at the lowest confidence: they identify the machine and say
    /// nothing about the service, which the corpus has already named.
    fn analyze(
        &self,
        _ctx: &PortContext,
        responses: &ResponseSet,
        _collected: &Collected,
    ) -> Vec<Evidence> {
        let names = responses
            .banners
            .iter()
            // An LDAPMessage opens with SEQUENCE, which as text is `0`; checked
            // before anything is copied, since this runs on every banner.
            .filter(|banner| banner.as_bytes().first() == Some(&SEQUENCE))
            .map(|banner| root_dse_names(&super::extract::reply_bytes(banner)))
            .find(|names| !names.is_empty());

        match names {
            Some(names) => vec![Evidence::new(self.id(), Confidence::Heuristic).with_names(names)],
            None => Vec::new(),
        }
    }
}

/// The names the root entry in `reply` gives for the controller serving it,
/// in the order the entry lists them.
///
/// `reply` is what the search drew: an LDAPMessage holding a SearchResultEntry
/// (RFC 4511 §4.5.2) whose `objectName` is empty, which is what makes it the
/// root entry, and usually a SearchResultDone behind it. An entry for any
/// other object names nothing here.
///
/// Read attribute by attribute, and stopped at the first the bytes do not hold
/// whole, so a reply cut short by a read limit still gives up the names ahead
/// of the cut. An Active Directory root entry runs to several kilobytes, and
/// `dnsHostName` sits past most of them. The first value of each attribute is
/// taken, which is the only one any of the three has.
#[must_use]
pub(super) fn root_dse_names(reply: &[u8]) -> Vec<HostName> {
    let Some(attributes) = root_entry_attributes(reply) else {
        return Vec::new();
    };

    let mut names = Vec::new();
    let mut rest = attributes;
    while let Some((tag, attribute, after)) = element(rest) {
        rest = after;
        if tag != SEQUENCE {
            break;
        }
        let Some((kind, value)) = named_value(attribute) else {
            continue;
        };
        if names.iter().any(|name: &HostName| name.kind() == kind) {
            continue;
        }
        let name = match kind {
            NameKind::Host => Some(value.to_owned()),
            _ => dns_name_of(value),
        };
        names.extend(name.and_then(|name| HostName::new(kind, NameSource::Ldap, &name)));
    }
    names
}

/// The attribute list of the root entry at the start of `reply`, as far as the
/// reply holds it.
///
/// Every enclosing element is allowed to run past the end of the reply, since
/// that is what a truncated one looks like; what is inside is read only where
/// it is whole.
fn root_entry_attributes(reply: &[u8]) -> Option<&[u8]> {
    let message = open(reply, SEQUENCE)?;
    let (tag, _, rest) = element(message)?;
    if tag != INTEGER {
        return None;
    }
    let entry = open(rest, SEARCH_RESULT_ENTRY)?;
    let (tag, object_name, rest) = element(entry)?;
    if tag != OCTET_STRING || !object_name.is_empty() {
        return None;
    }
    open(rest, SEQUENCE)
}

/// Which of the three names an attribute carries, and its first value, or
/// `None` for every other attribute and for one that is not text.
fn named_value(attribute: &[u8]) -> Option<(NameKind, &str)> {
    let (tag, description, rest) = element(attribute)?;
    if tag != OCTET_STRING {
        return None;
    }
    // An attribute description is matched without regard to case (RFC 4512
    // §2.5), and a directory may write it however it likes.
    let description = std::str::from_utf8(description).ok()?;
    let kind = [
        ("dnsHostName", NameKind::Host),
        ("defaultNamingContext", NameKind::Domain),
        ("rootDomainNamingContext", NameKind::Forest),
    ]
    .into_iter()
    .find_map(|(name, kind)| name.eq_ignore_ascii_case(description).then_some(kind))?;

    let (tag, values, _) = element(rest)?;
    if tag != SET {
        return None;
    }
    let (tag, value, _) = element(values)?;
    if tag != OCTET_STRING {
        return None;
    }
    Some((kind, std::str::from_utf8(value).ok()?))
}

/// The DNS name a naming context spells, `corp.example` for
/// `DC=corp,DC=example`, or `None` for one with any component that is not a
/// domain component.
///
/// A component escaped or joined with another (RFC 4514 §2.4, §2.2) is refused
/// with the rest, since neither can be a DNS label and reading one as a label
/// would report a domain the directory never named.
fn dns_name_of(context: &str) -> Option<String> {
    let labels = context
        .split(',')
        .map(|component| {
            let (attribute, value) = component.split_once('=')?;
            let value = value.trim();
            let label = attribute.trim().eq_ignore_ascii_case("dc")
                && !value.is_empty()
                && !value.contains(['\\', '+', '"']);
            label.then_some(value)
        })
        .collect::<Option<Vec<&str>>>()?;
    Some(labels.join("."))
}

/// The content of the element at the start of `bytes` if its tag is `tag`, as
/// much of it as `bytes` holds.
fn open(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    let (found, length, at) = header(bytes)?;
    if found != tag {
        return None;
    }
    let end = at.saturating_add(length).min(bytes.len());
    bytes.get(at..end)
}

/// The element at the start of `bytes`: its tag, its content, and what follows
/// it. `None` where `bytes` does not hold the whole element.
fn element(bytes: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let (tag, length, at) = header(bytes)?;
    let end = at.checked_add(length)?;
    Some((tag, bytes.get(at..end)?, bytes.get(end..)?))
}

/// The tag of the element at the start of `bytes`, the length its header
/// states, and how many bytes the header takes.
///
/// The length in either definite form (X.690 §8.1.3), the long one in up to
/// four bytes, which is what Active Directory writes everywhere. The
/// indefinite form is refused, as RFC 4511 §5.1 has every LDAP encoder refuse
/// it.
fn header(bytes: &[u8]) -> Option<(u8, usize, usize)> {
    let tag = *bytes.first()?;
    let first = *bytes.get(1)?;
    if first < 0x80 {
        return Some((tag, usize::from(first), 2));
    }
    let count = usize::from(first & 0x7F);
    if count == 0 || count > 4 {
        return None;
    }
    let length = bytes
        .get(2..2 + count)?
        .iter()
        .fold(0usize, |length, byte| (length << 8) | usize::from(*byte));
    Some((tag, length, 2 + count))
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
    use crate::testing::loopback::accept_from_this_process;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A BER element with its length in the four-byte form Active Directory
    /// writes every length in.
    fn ad(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag, 0x84];
        out.extend_from_slice(&(content.len() as u32).to_be_bytes());
        out.extend_from_slice(content);
        out
    }

    /// One attribute of an entry: its description and its values.
    fn attribute(description: &str, values: &[&str]) -> Vec<u8> {
        let values: Vec<u8> = values
            .iter()
            .flat_map(|value| ad(OCTET_STRING, value.as_bytes()))
            .collect();
        ad(
            SEQUENCE,
            &[ad(OCTET_STRING, description.as_bytes()), ad(SET, &values)].concat(),
        )
    }

    /// A SearchResultEntry for `object`, holding `attributes`, answering
    /// message 2, which is the corpus's search.
    fn entry(object: &str, attributes: &[Vec<u8>]) -> Vec<u8> {
        let body = [
            ad(OCTET_STRING, object.as_bytes()),
            ad(SEQUENCE, &attributes.concat()),
        ]
        .concat();
        ad(
            SEQUENCE,
            &[vec![INTEGER, 1, 2], ad(SEARCH_RESULT_ENTRY, &body)].concat(),
        )
    }

    /// A SearchResultDone reporting success, which follows the entry.
    fn done() -> Vec<u8> {
        ad(
            SEQUENCE,
            &[
                vec![INTEGER, 1, 2],
                ad(0x65, b"\x0a\x01\x00\x04\x00\x04\x00"),
            ]
            .concat(),
        )
    }

    /// A domain controller's root entry: the attributes that name it among
    /// ones that do not, in the order Active Directory lists them.
    fn controller() -> Vec<u8> {
        [
            entry(
                "",
                &[
                    attribute("currentTime", &["20260926120000.0Z"]),
                    attribute(
                        "namingContexts",
                        &["DC=corp,DC=example", "CN=Configuration,DC=corp,DC=example"],
                    ),
                    attribute("defaultNamingContext", &["DC=corp,DC=example"]),
                    attribute("rootDomainNamingContext", &["DC=corp,DC=example"]),
                    attribute("supportedLDAPVersion", &["3", "2"]),
                    attribute("dnsHostName", &["dc01.corp.example"]),
                    attribute("domainControllerFunctionality", &["7"]),
                ],
            ),
            done(),
        ]
        .concat()
    }

    fn named(names: &[HostName]) -> Vec<(NameKind, &str)> {
        names
            .iter()
            .map(|name| (name.kind(), name.name()))
            .collect()
    }

    /// The root entry names the controller, its domain and its forest, the
    /// two naming contexts read back into the DNS names they spell.
    #[test]
    fn a_root_entry_names_the_controller_its_domain_and_its_forest() {
        assert_eq!(
            named(&root_dse_names(&controller())),
            [
                (NameKind::Domain, "corp.example"),
                (NameKind::Forest, "corp.example"),
                (NameKind::Host, "dc01.corp.example"),
            ]
        );
    }

    /// What the analyzer reads is the reply after it became the text the
    /// corpus matches, and a controller's four-byte lengths are the high bytes
    /// that reading has to give back exactly.
    #[test]
    fn the_names_survive_the_reply_becoming_text() {
        let text = super::super::extract::reply_text(&controller());
        assert_eq!(super::super::extract::reply_bytes(&text), controller());
    }

    /// A reply cut short by a read limit gives up every name ahead of the cut
    /// and nothing past it; and no cut anywhere makes the reader fail.
    #[test]
    fn a_truncated_entry_gives_up_the_names_ahead_of_the_cut() {
        let reply = controller();
        let cut = reply
            .windows(b"supportedLDAPVersion".len())
            .position(|window| window == b"supportedLDAPVersion")
            .expect("the attribute is there");
        assert_eq!(
            named(&root_dse_names(&reply[..cut])),
            [
                (NameKind::Domain, "corp.example"),
                (NameKind::Forest, "corp.example"),
            ]
        );
        for end in 0..reply.len() {
            let _ = root_dse_names(&reply[..end]);
        }
    }

    /// Only the root entry speaks for the server. An entry for any other
    /// object describes that object, and a directory that names its
    /// partitions some other way names no domain.
    #[test]
    fn only_the_root_entry_and_only_a_domain_shaped_context_name_anything() {
        let other = entry(
            "CN=someone,DC=corp,DC=example",
            &[attribute("dnsHostName", &["someone.corp.example"])],
        );
        assert!(root_dse_names(&other).is_empty());

        let openldap = entry(
            "",
            &[
                attribute("defaultNamingContext", &["o=example"]),
                attribute("rootDomainNamingContext", &["OU=x,DC=corp,DC=example"]),
                attribute("DNSHOSTNAME", &["ldap.example"]),
            ],
        );
        assert_eq!(
            named(&root_dse_names(&openldap)),
            [(NameKind::Host, "ldap.example")],
            "a description is matched whatever its case"
        );
    }

    /// A directory answering the corpus's bind and search, as a controller
    /// does. Each request is answered with the next reply in `replies`.
    async fn directory(replies: Vec<Vec<u8>>) -> std::net::SocketAddr {
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("a socket");
        let addr = listener.local_addr().expect("its address");
        tokio::spawn(async move {
            while let Ok(mut sock) = accept_from_this_process(&listener).await {
                let replies = replies.clone();
                tokio::spawn(async move {
                    let mut request = [0u8; 256];
                    for reply in replies {
                        if !matches!(sock.read(&mut request).await, Ok(read) if read > 0) {
                            return;
                        }
                        let _ = sock.write_all(&reply).await;
                    }
                    let _ = sock.read(&mut request).await;
                });
            }
        });
        addr
    }

    /// A directory's names are the machine's whether or not any rule names
    /// the service that gave them. A root entry under a message id of two
    /// bytes, as the three hundredth message on a connection has, is one no
    /// rule reads as LDAP, and its names still reach the host.
    #[tokio::test]
    async fn a_directory_no_rule_names_still_names_its_host() {
        use crate::model::port::{PortState, Protocol};

        let mut entry = controller();
        // The message id `02 01 02` becomes `02 02 01 2c`, and the envelope's
        // four-byte length one longer for it.
        assert_eq!(&entry[6..9], [INTEGER, 1, 2]);
        entry.splice(6..9, [INTEGER, 2, 0x01, 0x2c]);
        let length = u32::from_be_bytes(entry[2..6].try_into().expect("four bytes")) + 1;
        entry[2..6].copy_from_slice(&length.to_be_bytes());

        let addr = directory(vec![entry]).await;
        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connects");
        let port = crate::fingerprint::baseline_port(40389, Protocol::Tcp, PortState::Open);
        let identified = crate::fingerprint::fingerprint_tcp_detailed(
            stream,
            port,
            crate::config::ServiceDetection::Probe,
        )
        .await;

        assert!(
            identified
                .port
                .service()
                .is_none_or(|service| service.name() != "ldap"),
            "a rule named the service, so this checks nothing: {:?}",
            identified.port.service()
        );
        assert_eq!(
            named(&identified.about_the_host.names),
            [
                (NameKind::Domain, "corp.example"),
                (NameKind::Forest, "corp.example"),
                (NameKind::Host, "dc01.corp.example"),
            ]
        );
    }

    /// **A controller's names reach its host, over sockets end to end**: the
    /// corpus's bind and root DSE search, the reply read as text, and the
    /// names read back out of it.
    #[tokio::test]
    async fn a_controller_s_names_reach_its_host() {
        use crate::model::port::{PortState, Protocol};

        let bound = ad(
            SEQUENCE,
            &[
                vec![INTEGER, 1, 1],
                ad(0x61, b"\x0a\x01\x00\x04\x00\x04\x00"),
            ]
            .concat(),
        );
        let addr = directory(vec![bound, controller()]).await;

        let stream = tokio::net::TcpStream::connect(addr)
            .await
            .expect("connects");
        let port = crate::fingerprint::baseline_port(389, Protocol::Tcp, PortState::Open);
        let identified = crate::fingerprint::fingerprint_tcp_detailed(
            stream,
            port,
            crate::config::ServiceDetection::Probe,
        )
        .await;

        assert_eq!(identified.port.service().map(|s| s.name()), Some("ldap"));
        assert_eq!(
            named(&identified.about_the_host.names),
            [
                (NameKind::Domain, "corp.example"),
                (NameKind::Forest, "corp.example"),
                (NameKind::Host, "dc01.corp.example"),
            ]
        );
        assert!(
            identified
                .about_the_host
                .names
                .iter()
                .all(|name| name.source() == NameSource::Ldap)
        );
    }
}
