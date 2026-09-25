// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Who a web port is asked for
//!
//! An HTTP request names the site it wants in its `Host` header, and a
//! redirect names where to look next as a URL. Both are written in the
//! authority form of RFC 3986 section 3.2: a host, and a port where it is not
//! the scheme's default. [`Authority`] is the one place a port being
//! identified is written in that form and read back out of it, so a request
//! and the check on where its redirect leads cannot disagree about what the
//! port is called.

use std::net::{IpAddr, SocketAddr};

/// The port being identified, as a web client addresses it.
#[derive(Debug, Clone)]
pub(crate) struct Authority {
    /// Where the port was reached.
    socket: SocketAddr,
    /// Whether it is spoken to through TLS, which makes the scheme `https`
    /// and its default port 443 rather than `http`'s 80.
    tls: bool,
}

impl Authority {
    /// The port at `socket`, spoken to in the clear.
    pub(crate) fn new(socket: SocketAddr) -> Self {
        Self { socket, tls: false }
    }

    /// Where the port was reached.
    pub(crate) fn socket(&self) -> SocketAddr {
        self.socket
    }

    /// The scheme a URL for this port is written with.
    fn scheme(&self) -> &'static str {
        match self.tls {
            true => "https",
            false => "http",
        }
    }

    /// The port a URL in [`scheme`](Self::scheme) means when it names none.
    fn default_port(&self) -> u16 {
        match self.tls {
            true => 443,
            false => 80,
        }
    }

    /// The host half, as a URL or a `Host` header writes it.
    ///
    /// An IPv6 address goes in brackets, since the colons in it would
    /// otherwise read as the separator before a port. Its zone does not: RFC
    /// 6874 allows one only in a URI and not in a request, and it names an
    /// interface of this machine, which is nothing to the server.
    fn host(&self) -> String {
        match self.socket.ip() {
            IpAddr::V4(v4) => v4.to_string(),
            IpAddr::V6(v6) => format!("[{v6}]"),
        }
    }

    /// The value of a `Host` header for this port: the host, then the port
    /// where it is not the scheme's default, as RFC 9110 section 7.2 has it.
    pub(crate) fn header(&self) -> String {
        match self.socket.port() == self.default_port() {
            true => self.host(),
            false => format!("{}:{}", self.host(), self.socket.port()),
        }
    }

    /// The path of an absolute `url`, when it leads back to this port.
    ///
    /// A URL leads back when its scheme is the one this port is spoken in and
    /// its authority names this address and this port, the port written out
    /// or implied by the scheme. A different port is a different service, and
    /// a different scheme is another conversation with this one, `https` from
    /// a port spoken to in the clear or `http` from one spoken to through TLS,
    /// so either is declined rather than guessed at. A scheme-relative
    /// reference, `//host/path`, takes the scheme it was served over.
    ///
    /// Compared as addresses rather than as text, so the two spellings of one
    /// IPv6 address are one address. Credentials in the authority are
    /// declined: a redirect carrying them is not one to replay.
    pub(crate) fn path_of(&self, url: &str) -> Option<String> {
        let rest = match url.split_once("://") {
            Some((scheme, rest)) if scheme.eq_ignore_ascii_case(self.scheme()) => rest,
            Some(_) => return None,
            None => url.strip_prefix("//")?,
        };

        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(at) => rest.split_at(at),
            None => (rest, ""),
        };
        if authority.contains('@') {
            return None;
        }

        let (host, port) = split_authority(authority)?;
        let port = match port {
            Some(port) => port,
            None => self.default_port(),
        };
        if port != self.socket.port() || !self.names(host) {
            return None;
        }

        Some(match path {
            "" => "/".to_string(),
            query if !query.starts_with('/') => format!("/{query}"),
            path => path.to_string(),
        })
    }

    /// Whether `host`, as a URL writes it with any brackets taken off, names
    /// this port's host.
    fn names(&self, host: &str) -> bool {
        host.parse::<IpAddr>()
            .is_ok_and(|address| address == self.socket.ip())
    }
}

/// The host and the port of a URL's authority, with an IPv6 address's brackets
/// taken off. `None` for an authority that is neither shape, or whose port is
/// not a number.
fn split_authority(authority: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = match authority.strip_prefix('[') {
        Some(bracketed) => {
            let (host, after) = bracketed.split_once(']')?;
            match after {
                "" => (host, None),
                port => (host, Some(port.strip_prefix(':')?)),
            }
        }
        None => match authority.rsplit_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        },
    };
    if host.is_empty() {
        return None;
    }
    // An empty port is the default, as RFC 3986 section 3.2.3 allows.
    let port = match port {
        None | Some("") => None,
        Some(port) => Some(port.parse().ok()?),
    };
    Some((host, port))
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

    fn at(socket: &str) -> Authority {
        Authority::new(socket.parse().expect("a literal socket address"))
    }

    /// The port is left off where the scheme implies it, which is how a
    /// browser writes it and what a virtual host is configured to expect.
    #[test]
    fn a_host_header_names_the_port_only_where_the_scheme_does_not() {
        assert_eq!(at("192.0.2.1:80").header(), "192.0.2.1");
        assert_eq!(at("192.0.2.1:8080").header(), "192.0.2.1:8080");
        assert_eq!(at("[2001:db8::1]:80").header(), "[2001:db8::1]");
        assert_eq!(at("[2001:db8::1]:8080").header(), "[2001:db8::1]:8080");
    }

    /// Two spellings of one IPv6 address are one address, and the default
    /// port may be written or left out.
    #[test]
    fn a_url_leads_back_whatever_spelling_names_the_same_address_and_port() {
        let v6 = at("[2001:db8::1]:80");
        assert_eq!(v6.path_of("http://[2001:db8::1]/a").as_deref(), Some("/a"));
        assert_eq!(
            v6.path_of("http://[2001:DB8:0::1]:80/a").as_deref(),
            Some("/a")
        );
        assert_eq!(v6.path_of("HTTP://[2001:db8::1]").as_deref(), Some("/"));
        assert_eq!(v6.path_of("//[2001:db8::1]?x=1").as_deref(), Some("/?x=1"));
    }

    /// Anything that is not this port in this scheme is somewhere else.
    #[test]
    fn a_url_naming_anything_else_does_not_lead_back() {
        let here = at("192.0.2.1:8080");
        for url in [
            "http://192.0.2.2:8080/",
            "http://192.0.2.1/",
            "http://192.0.2.1:8081/",
            "https://192.0.2.1:8080/",
            "http://user@192.0.2.1:8080/",
            "http://192.0.2.1:port/",
            "http://:8080/",
            "http://[2001:db8::1]:8080/",
        ] {
            assert_eq!(here.path_of(url), None, "`{url}` does not lead back");
        }
    }
}
