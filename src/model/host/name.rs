// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # The names a host gives for itself
//!
//! A Windows server answering an SMB session setup names itself before anyone has
//! authenticated: its NetBIOS name, its DNS name, its domain and its forest. A domain
//! controller's LDAP root entry says the same to anyone who asks. These are among the
//! most useful facts a scan learns, and among the most sensitive a report carries,
//! since a domain name names the organisation.
//!
//! [`HostName`] holds one name, what it names, and which protocol said it. A report
//! masks these where asked, as it masks a hostname; a service's description is never
//! masked, so they are kept out of it.
//!
//! ## Separate from the hostname
//!
//! [`Host::hostname`](super::Host::hostname) is what name resolution answered for the
//! address (the hosts file, a reverse lookup, multicast DNS, a DHCP request), and stays
//! the name a host is displayed under. Nothing here displaces or fills it.
//!
//! A hostname is what the network calls an address, and the rest of a scan works from
//! it: the multicast DNS device-info question is asked under it, and a default name
//! such as `DESKTOP-` is itself an operating-system witness. A name a service states is
//! the machine's claim about itself. Promoted into the hostname, an NTLM challenge would
//! count twice toward the same operating system.
//!
//! Names resolution found are not repeated here either.

use std::fmt;

/// The longest name recorded, in characters.
///
/// A DNS name is at most 253 characters written out (RFC 1035 §2.3.4) and a NetBIOS
/// name fifteen. This bounds a peer sending a field the length of its whole reply.
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
    /// A Kerberos realm is recorded as one, in the KDC's case: `CORP.EXAMPLE`. RFC 4120
    /// §6.1 gives realms the style of a domain name, Active Directory uses the DNS name
    /// in capitals, and the source already says it was a realm.
    Domain,
    /// The NetBIOS name of the domain or workgroup the machine belongs to:
    /// `CORP`.
    ///
    /// On a machine joined to no domain this is whatever it answers for
    /// itself, often its own name, and it is recorded as stated.
    NetbiosDomain,
    /// The DNS name of the forest root, the domain at the top of the machine's domain
    /// tree. Usually equal to [`Domain`](Self::Domain), and recorded anyway as a
    /// separate claim.
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
/// A variant exists only once something records a name under it.
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
    /// The name table a NetBIOS node-status response lists (RFC 1002
    /// §4.2.18), which a Windows or Samba host sends to anyone asking on UDP
    /// 137: the machine's own name, registered for the workstation service,
    /// and the domain or workgroup it joined, registered as a group.
    Netbios,
    /// The Host Name attribute an L2TP concentrator puts in its answer to a
    /// tunnel request (RFC 2661 §4.4.3), sent to anyone proposing a tunnel on
    /// UDP 1701 before anything is authenticated: the machine's own name.
    L2tp,
}

impl NameSource {
    /// Every source this build knows, in declaration order.
    pub const ALL: &'static [Self] = &[
        Self::Ntlm,
        Self::Ldap,
        Self::Kerberos,
        Self::Smb,
        Self::Netbios,
        Self::L2tp,
    ];

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
            Self::Netbios => "NetBIOS",
            Self::L2tp => "L2TP",
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
    /// Surrounding whitespace is trimmed, and the rest is refused if empty, longer than
    /// any protocol allows, or holding a control character (which would break a
    /// report's line). Nothing else is refused; every exporter escapes names as
    /// untrusted text.
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

    /// Empty, control-character and oversized names are refused.
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

    /// The machine sorts before what it belongs to, whichever arrived first.
    #[test]
    fn names_order_by_what_they_name_before_who_said_them() {
        let forest = HostName::new(NameKind::Forest, NameSource::Ntlm, "corp.example").unwrap();
        let host = HostName::new(NameKind::Host, NameSource::Ldap, "dc01.corp.example").unwrap();
        assert!(host < forest);
    }
}
