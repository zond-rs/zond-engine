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
//! corpus's probe asks for and RFC 4512 §5.1 makes readable without
//! credentials. The corpus matches the answer as text to name the directory and
//! release; this analyzer lifts out the three values that name a domain
//! controller:
//!
//! | attribute | kind |
//! |---|---|
//! | `dnsHostName` | [`Host`](NameKind::Host), the controller's DNS name |
//! | `defaultNamingContext` | [`Domain`](NameKind::Domain), the domain it serves |
//! | `rootDomainNamingContext` | [`Forest`](NameKind::Forest), the forest's root domain |
//!
//! The naming contexts are distinguished names such as `DC=corp,DC=example`.
//! Active Directory names a partition after the domain's DNS name, one label per
//! component, so each is read back into that DNS name. A context with any other
//! component (OpenLDAP's `o=example`) names no domain.
//!
//! These are recorded on the host as [`HostName`]s, which reports mask (see
//! [`name`](crate::model::host::name)).
//!
//! ## Passive
//!
//! The entry is already in the responses the probe drew. It is read back out of
//! text; see [`reply_bytes`](super::extract::reply_bytes) for how exact that is.

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

    /// Any TCP port; `analyze` gates on the reply itself.
    fn interested(&self, ctx: &PortContext) -> bool {
        ctx.protocol == crate::model::port::Protocol::Tcp
    }

    // Passive. See the module docs.

    /// The names in the first root entry among the responses, as one
    /// observation at the lowest confidence, since they identify the machine and
    /// not the service.
    fn analyze(
        &self,
        _ctx: &PortContext,
        responses: &ResponseSet,
        _collected: &Collected,
    ) -> Vec<Evidence> {
        let names = responses
            .banners
            .iter()
            // An LDAPMessage opens with SEQUENCE (`0` as text). Cheap check on
            // every banner before copying.
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
/// (RFC 4511 §4.5.2) with an empty `objectName`, which marks the root entry,
/// usually followed by a SearchResultDone. An entry for any other object yields
/// nothing.
///
/// Reading stops at the first attribute the bytes do not hold whole, so a reply
/// cut short by a read limit still yields the names before the cut. An Active
/// Directory root entry runs to several kilobytes, with `dnsHostName` near the
/// end. Each of the three attributes has one value.
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
/// Enclosing elements may run past the end of a truncated reply; their contents
/// are read only where whole.
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
    // Attribute descriptions are case-insensitive (RFC 4512 §2.5).
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
/// An escaped or multi-valued component (RFC 4514 §2.4, §2.2) cannot be a DNS
/// label, so the context is refused.
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
/// Either definite length form (X.690 §8.1.3), the long one in up to four bytes,
/// which Active Directory uses everywhere. The indefinite form is refused, as
/// RFC 4511 §5.1 forbids it.
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

    /// A BER element with a four-byte length, as Active Directory writes them.
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
    /// message 2 (the corpus's search).
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

    /// A domain controller's root entry, attributes in Active Directory's order.
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

    /// The root entry names the controller, its domain and its forest.
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

    /// The reply is read back from the corpus's text form, and the four-byte
    /// lengths' high bytes must survive that.
    #[test]
    fn the_names_survive_the_reply_becoming_text() {
        let text = super::super::extract::reply_text(&controller());
        assert_eq!(super::super::extract::reply_bytes(&text), controller());
    }

    /// A truncated reply yields every name before the cut, and no cut panics.
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

    /// Only the root entry counts, and a non-`DC` naming context names no domain.
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

    /// The names reach the host even when no rule names the service: here a
    /// two-byte message id, which no rule reads as LDAP.
    #[tokio::test]
    async fn a_directory_no_rule_names_still_names_its_host() {
        use crate::model::port::{PortState, Protocol};

        let mut entry = controller();
        // The message id `02 01 02` becomes `02 02 01 2c`, one byte longer.
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

    /// A controller's names reach its host over sockets, end to end.
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
