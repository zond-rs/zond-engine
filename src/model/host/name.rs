// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The names a host gives for itself
//!
//! A Windows server answering an SMB session setup names itself before anyone
//! has authenticated: its NetBIOS name, its DNS name, the domain it belongs to
//! and the forest that domain sits in. A domain controller's LDAP root entry
//! says the same, readable by anyone who asks. These are some of the most
//! useful facts a scan learns about a machine, and some of the most sensitive
//! a report can carry, since a domain name names the organisation.
//!
//! [`HostName`] is where they are kept: one name, what it names, and which
//! protocol said it. A report masks every one of them where it is asked to,
//! the way it masks a hostname. That is why they are not a service's
//! description: a port's extra detail is a service's account of itself and no
//! report masks it, so a name put there would reach every redacted document
//! in the clear.
//!
//! ## Not the hostname
//!
//! [`Host::hostname`](super::Host::hostname) is what name resolution answered
//! for the address: the hosts file, a reverse lookup, the host's own multicast
//! DNS responder or the DHCP request it broadcast, ranked by the resolver that
//! asked. It stays the name a host is displayed under, and nothing recorded
//! here displaces it or fills it in.
//!
//! The two answer different questions. A hostname is what the network calls an
//! address, and it is what the rest of a scan works from: the multicast DNS
//! device-info question is asked under it, and a default name such as
//! `DESKTOP-` is read from it as a witness about the operating system in its
//! own right. A name a service states is that service's claim about the
//! machine. Promoted into the hostname, an NTLM challenge would count twice
//! towards the same operating system, once for the build it states and once
//! for the default name beside it, and a report would show a machine's claim
//! about itself in the place a reader takes for the network's answer.
//!
//! Names resolution found are therefore not repeated here either. The hostname
//! already carries its own answer, and a copy here would be a second account of
//! one fact that two readers, a merge and a comparison, would each have to keep
//! in step with the first.

use std::fmt;

/// The longest name recorded, in characters.
///
/// A DNS name is at most 253 characters written out (RFC 1035 §2.3.4) and a
/// NetBIOS name fifteen, so nothing a host legitimately states comes near it.
/// What it bounds is a peer that sends a field the length of its whole reply,
/// which would otherwise be carried into every report of the host.
const MAX_NAME_CHARS: usize = 255;

/// What a name names.
///
/// Ordered as a reader meets them: the machine before what it belongs to, and
/// the name a resolver would answer for before the flat one beside it.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameKind {
    /// The machine's own DNS name, qualified where the source qualified it:
    /// `dc01.corp.example`.
    Host,
    /// The machine's NetBIOS name, the flat name of fifteen characters or fewer
    /// that Windows networking addresses it by: `DC01`.
    NetbiosHost,
    /// The DNS name of the domain the machine belongs to: `corp.example`.
    ///
    /// A Kerberos realm is recorded as one, in the case the KDC wrote it:
    /// `CORP.EXAMPLE`. RFC 4120 §6.1 gives realms the style of a domain name,
    /// Active Directory makes a domain's realm its DNS name in capitals, and
    /// the source says the name was a realm, so a separate kind would put the
    /// one fact under two headings.
    Domain,
    /// The NetBIOS name of the domain or workgroup the machine belongs to:
    /// `CORP`.
    ///
    /// On a machine joined to no domain this is whatever it answers for
    /// itself, often its own name, and it is recorded as stated.
    NetbiosDomain,
    /// The DNS name of the forest root, the domain at the top of the tree the
    /// machine's domain belongs to. Equal to [`Domain`](Self::Domain) in a
    /// forest of one domain, which is most of them, and recorded anyway: the
    /// two are separate claims, and a report that left one out would say
    /// nothing about which of them the host made.
    Forest,
}

impl NameKind {
    /// Every kind this build knows, in declaration order.
    ///
    /// Every round trip through [`wire`](crate::record::wire) is tested over
    /// this, so a kind added without a spelling fails until it has one.
    pub const ALL: &'static [Self] = &[
        Self::Host,
        Self::NetbiosHost,
        Self::Domain,
        Self::NetbiosDomain,
        Self::Forest,
    ];

    /// How a kind is written for a person to read.
    ///
    /// Separate from [`name_kind_name`](crate::record::wire::name_kind_name),
    /// which is the machine's spelling and may never change.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::NetbiosHost => "NetBIOS host",
            Self::Domain => "domain",
            Self::NetbiosDomain => "NetBIOS domain",
            Self::Forest => "forest",
        }
    }
}

/// Which protocol a host stated a name in.
///
/// A variant exists only once something records a name under it, the rule
/// [`NetworkRole`](super::NetworkRole) keeps: a source nothing reads would
/// promise a consumer the engine asks it, and an empty list would then mean
/// "said none" where it means "never asked".
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NameSource {
    /// The target information of an NTLM challenge (MS-NLMP 2.2.2.1), which an
    /// SMB server sends in answer to a session setup before anything is
    /// authenticated. Windows and Samba both fill in all five names.
    Ntlm,
    /// The root DSE of an LDAP directory (RFC 4512 §5.1), which a directory
    /// serves to an anonymous search: `dnsHostName`, and the naming contexts a
    /// domain and a forest are read from.
    Ldap,
    /// The realm a Kerberos KDC names in a `KRB-ERROR` (RFC 4120 §5.9.1),
    /// which it sends to an unauthenticated request for a realm it does not
    /// serve. Recorded only where it differs from the realm the request named,
    /// since a KDC otherwise repeats what it was asked about.
    Kerberos,
    /// The primary domain an SMB1 server names in answer to a session setup
    /// (MS-CIFS 2.2.4.53.2), the NetBIOS name of the domain or workgroup it
    /// belongs to. Asked of a server that speaks SMB1, and of one whose SMB2
    /// answer named no Windows build.
    Smb,
}

impl NameSource {
    /// Every source this build knows, in declaration order.
    pub const ALL: &'static [Self] = &[Self::Ntlm, Self::Ldap, Self::Kerberos, Self::Smb];

    /// How a source is written for a person to read.
    ///
    /// Separate from
    /// [`name_source_name`](crate::record::wire::name_source_name), for the
    /// reason [`NameKind::label`] is.
    pub const fn label(self) -> &'static str {
        match self {
            Self::Ntlm => "NTLM",
            Self::Ldap => "LDAP",
            Self::Kerberos => "Kerberos",
            Self::Smb => "SMB",
        }
    }
}

/// One name a host gave for itself, what it names, and which protocol it was
/// given in.
///
/// Ordered by kind, then source, then the name, so a host's names read as the
/// machine first and what it belongs to after, whichever order they arrived
/// in.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct HostName {
    kind: NameKind,
    source: NameSource,
    name: String,
}

impl HostName {
    /// A name as a host stated it, or `None` where it states nothing a report
    /// should carry.
    ///
    /// Surrounding whitespace is trimmed, and what is left is refused where it
    /// is empty, longer than any name a protocol allows, or holds a control
    /// character. Every one of those is a peer's bytes that name nothing: an
    /// empty field is a server declining to answer, and a line break in a name
    /// would split the line a report writes it on.
    ///
    /// Nothing else is refused. A name is a stranger's text and every exporter
    /// escapes it as one; refusing what looks unusual here would decide on the
    /// reader's behalf which of a host's claims to hear.
    #[must_use]
    pub fn new(kind: NameKind, source: NameSource, name: &str) -> Option<Self> {
        let name = name.trim();
        let valid = !name.is_empty()
            && name.chars().count() <= MAX_NAME_CHARS
            && !name.chars().any(char::is_control);
        valid.then(|| Self {
            kind,
            source,
            name: name.to_owned(),
        })
    }

    /// What the name names.
    pub fn kind(&self) -> NameKind {
        self.kind
    }

    /// Which protocol stated it.
    pub fn source(&self) -> NameSource {
        self.source
    }

    /// The name, as the host stated it.
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl fmt::Display for HostName {
    /// `corp.example (domain, NTLM)`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} ({}, {})",
            self.name,
            self.kind.label(),
            self.source.label()
        )
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A name is kept as stated, less the whitespace around it.
    #[test]
    fn a_name_is_kept_as_the_host_stated_it() {
        let name = HostName::new(NameKind::Domain, NameSource::Ntlm, " corp.example ")
            .expect("an ordinary domain name");
        assert_eq!(name.name(), "corp.example");
        assert_eq!(name.to_string(), "corp.example (domain, NTLM)");
    }

    /// Each of these is a peer's field that names nothing, and a report that
    /// carried one would hold an empty entry, a line broken in two, or a
    /// kilobyte of whatever the peer chose to send.
    #[test]
    fn a_field_that_names_nothing_is_refused() {
        for refused in ["", "   ", "dc01\ncorp", "dc01\0", &"a".repeat(256)] {
            assert_eq!(
                HostName::new(NameKind::Host, NameSource::Ldap, refused),
                None,
                "{refused:?}"
            );
        }
        assert!(HostName::new(NameKind::Host, NameSource::Ldap, &"a".repeat(255)).is_some());
    }

    /// The machine reads before what it belongs to, whichever arrived first,
    /// so two scans that heard the same names render them the same way.
    #[test]
    fn names_order_by_what_they_name_before_who_said_them() {
        let forest = HostName::new(NameKind::Forest, NameSource::Ntlm, "corp.example").unwrap();
        let host = HostName::new(NameKind::Host, NameSource::Ldap, "dc01.corp.example").unwrap();
        assert!(host < forest);
    }
}
