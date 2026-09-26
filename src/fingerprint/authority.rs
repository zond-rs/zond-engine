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
//!
//! ## Named where a target named it
//!
//! A server holding several sites at one address routes a request by the name
//! in it: the `Host` header, and before that the server name of a TLS
//! handshake. Asked with neither, it serves its default site, or refuses the
//! handshake outright where it keeps no certificate for a nameless client. So
//! where a target reached the address by a name, the port is asked for by that
//! name and the site identified is the one the target named. Elsewhere it is
//! asked for by its address, as a browser pointed at the address asks; a
//! placeholder such as `localhost` is a site no server was asked to hold, and
//! a request naming it is one no visitor sends.

use std::borrow::Cow;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rustls::pki_types::ServerName;

/// The port being identified, as a web client addresses it.
#[derive(Debug, Clone)]
pub(crate) struct Authority {
    /// Where the port was reached.
    socket: SocketAddr,
    /// The name a target reached the address by, where it named a host.
    name: Option<Arc<str>>,
    /// Whether it is spoken to through TLS, which makes the scheme `https`
    /// and its default port 443 rather than `http`'s 80.
    tls: bool,
}

impl Authority {
    /// The port at `socket`, spoken to in the clear.
    pub(crate) fn new(socket: SocketAddr) -> Self {
        Self {
            socket,
            name: None,
            tls: false,
        }
    }

    /// The port at `socket`, spoken to through `tunnel`.
    pub(crate) fn for_tunnel(
        socket: SocketAddr,
        tunnel: Option<crate::fingerprint::Tunnel>,
    ) -> Self {
        Self {
            socket,
            name: None,
            tls: matches!(tunnel, Some(crate::fingerprint::Tunnel::Tls)),
        }
    }

    /// The same port, asked for by `name` where there is one.
    pub(crate) fn named(mut self, name: Option<Arc<str>>) -> Self {
        self.name = name;
        self
    }

    /// The same port, spoken to through TLS.
    pub(crate) fn through_tls(&self) -> Self {
        Self {
            tls: true,
            ..self.clone()
        }
    }

    /// Whether the port is spoken to through TLS.
    pub(crate) fn is_tls(&self) -> bool {
        self.tls
    }

    /// The server name a TLS handshake with this port carries: the name, where
    /// it is one a handshake can carry, and otherwise the address, which puts
    /// no server name on the wire at all.
    pub(crate) fn server_name(&self) -> ServerName<'static> {
        self.name
            .as_deref()
            .and_then(|name| ServerName::try_from(name.to_string()).ok())
            .unwrap_or_else(|| ServerName::IpAddress(self.socket.ip().into()))
    }

    /// `payload` with the `Host` header of the HTTP request it carries set to
    /// this port's; see [`header`](Self::header).
    ///
    /// An authored probe is written once for every host, so the host it
    /// writes is a placeholder, and this is where the port being asked is put
    /// in its place. A payload that is not an HTTP/1 request, or that carries
    /// no `Host`, is sent as written, which leaves a probe for another protocol
    /// and a deliberate HTTP/1.0 request without one untouched.
    pub(crate) fn addressed<'a>(&self, payload: &'a [u8]) -> Cow<'a, [u8]> {
        self.with_host(payload, |_| true)
    }

    /// `payload` with the `Host` of the HTTP request it carries set to this
    /// port's, where that `Host` stands for the port rather than naming a site
    /// of its own.
    ///
    /// A detection is written once for every host, as a probe is, so the host
    /// it writes is ordinarily a stand-in: `localhost`, the address the
    /// detection was handed, or nothing. Each is replaced as
    /// [`addressed`](Self::addressed) replaces a probe's, so a detection asks
    /// for the site the target named. A `Host` naming any other site is the
    /// detection's question, how the server treats a name it may not hold, and
    /// is sent as written.
    pub(crate) fn readdressed<'a>(&self, payload: &'a [u8]) -> Cow<'a, [u8]> {
        self.with_host(payload, |value| self.stands_for_this_port(value))
    }

    /// `payload` with the value of its HTTP/1 request's `Host` header replaced
    /// by this port's [`header`](Self::header), where `replace` says so of the
    /// value it carries.
    fn with_host<'a>(&self, payload: &'a [u8], replace: impl Fn(&[u8]) -> bool) -> Cow<'a, [u8]> {
        let Some(head) = find(payload, b"\r\n\r\n") else {
            return Cow::Borrowed(payload);
        };
        let Some(line_end) = find(&payload[..head], b"\r\n") else {
            return Cow::Borrowed(payload);
        };
        if find(&payload[..line_end], b" HTTP/1.").is_none() {
            return Cow::Borrowed(payload);
        }

        // Each header line starts after a CRLF and runs to the next one.
        let mut at = line_end + 2;
        while at < head {
            let end = find(&payload[at..head], b"\r\n").map_or(head, |n| at + n);
            let line = &payload[at..end];
            if let Some(colon) = line.iter().position(|&byte| byte == b':')
                && line[..colon].eq_ignore_ascii_case(b"host")
            {
                if !replace(&line[colon + 1..]) {
                    return Cow::Borrowed(payload);
                }
                let mut addressed = Vec::with_capacity(payload.len() + 64);
                addressed.extend_from_slice(&payload[..at + colon + 1]);
                addressed.push(b' ');
                addressed.extend_from_slice(self.header().as_bytes());
                addressed.extend_from_slice(&payload[end..]);
                return Cow::Owned(addressed);
            }
            at = end + 2;
        }
        Cow::Borrowed(payload)
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
        if let Some(name) = &self.name {
            return name.to_string();
        }
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

    /// Whether the value of a `Host` header stands for this port: empty,
    /// `localhost`, its address in any spelling, or the name it is asked for
    /// by, with or without a port.
    fn stands_for_this_port(&self, value: &[u8]) -> bool {
        let Ok(value) = std::str::from_utf8(value) else {
            return false;
        };
        let value = value.trim();
        // A bare IPv6 address, as a template seeded with one writes it, reads
        // as a host and a port split at its last colon; it is taken whole
        // first.
        if value.is_empty()
            || value
                .parse::<IpAddr>()
                .is_ok_and(|address| address == self.socket.ip())
        {
            return true;
        }
        split_authority(value)
            .is_some_and(|(host, _)| host.eq_ignore_ascii_case("localhost") || self.names(host))
    }

    /// Whether `host`, as a URL writes it with any brackets taken off, names
    /// this port's host: its address, or the name it is asked for by. A name
    /// is compared without case and without a fully qualified name's trailing
    /// dot, as DNS compares names.
    fn names(&self, host: &str) -> bool {
        if host
            .parse::<IpAddr>()
            .is_ok_and(|address| address == self.socket.ip())
        {
            return true;
        }
        let bare = |name: &str| name.strip_suffix('.').unwrap_or(name).to_owned();
        self.name
            .as_deref()
            .is_some_and(|name| bare(name).eq_ignore_ascii_case(&bare(host)))
    }
}

/// Where `needle` first appears in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
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

    /// A named port is asked for by its name, which is what a virtual host
    /// is configured under, and through TLS the default port is 443.
    #[test]
    fn a_named_port_is_asked_for_by_its_name() {
        let named = at("192.0.2.1:8443").named(Some(Arc::from("box.example")));
        assert_eq!(named.header(), "box.example:8443");
        assert_eq!(named.through_tls().header(), "box.example:8443");
        let https = at("192.0.2.1:443").named(Some(Arc::from("box.example")));
        assert_eq!(https.through_tls().header(), "box.example");
        assert_eq!(https.header(), "box.example:443");
    }

    /// A handshake carries the name, and an address carries none, since an
    /// address in the server name extension is not allowed.
    #[test]
    fn a_handshake_carries_the_name_and_never_an_address() {
        let named = at("192.0.2.1:443").named(Some(Arc::from("box.example")));
        assert!(
            matches!(named.server_name(), ServerName::DnsName(dns) if dns.as_ref() == "box.example")
        );
        assert!(matches!(
            at("192.0.2.1:443").server_name(),
            ServerName::IpAddress(_)
        ));
    }

    /// The placeholder an authored probe carries becomes the port asked, and
    /// nothing else in the request moves.
    #[test]
    fn an_authored_request_is_addressed_to_the_port_asked() {
        let named = at("192.0.2.1:80").named(Some(Arc::from("box.example")));
        let probe = b"GET / HTTP/1.1\r\nHost: localhost\r\nAccept: */*\r\n\r\n";
        assert_eq!(
            &*named.addressed(probe),
            b"GET / HTTP/1.1\r\nHost: box.example\r\nAccept: */*\r\n\r\n"
        );
        let last = b"GET /v2/ HTTP/1.1\r\nhost:localhost\r\n\r\n";
        assert_eq!(
            &*at("[2001:db8::1]:5000").addressed(last),
            b"GET /v2/ HTTP/1.1\r\nhost: [2001:db8::1]:5000\r\n\r\n"
        );

        // Not an HTTP request, or one with no `Host`: sent as written.
        for untouched in [
            &b"GET / HTTP/1.0\r\n\r\n"[..],
            b"0011git-upload-pack /\0host=localhost\0",
            b"<stream:stream to='localhost'>",
            b"PING\r\nHost: localhost\r\n\r\n",
        ] {
            assert!(matches!(named.addressed(untouched), Cow::Borrowed(_)));
        }
    }

    /// A detection's stand-in for the port it asks is replaced whatever form
    /// it takes, and a `Host` naming another site is the detection's own
    /// question and goes as written.
    #[test]
    fn a_detection_request_is_addressed_only_where_it_stands_for_the_port() {
        let named = at("[2001:db8::1]:8080").named(Some(Arc::from("box.example")));
        let request = |host: &str| format!("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n").into_bytes();
        let addressed = request("box.example:8080");
        for stand_in in [
            "localhost",
            "LOCALHOST:80",
            "2001:db8::1",
            "[2001:db8::1]:8080",
            "box.example",
            "",
        ] {
            assert_eq!(
                &*named.readdressed(&request(stand_in)),
                &addressed[..],
                "`{stand_in}` stands for the port"
            );
        }
        for other in ["evil.example", "192.0.2.9", "[2001:db8::2]"] {
            assert!(
                matches!(named.readdressed(&request(other)), Cow::Borrowed(_)),
                "`{other}` names another site"
            );
        }
    }

    /// A redirect naming the name the port is asked for by leads back, which
    /// is how a virtual host sends a visitor to its own login page.
    #[test]
    fn a_url_naming_the_name_asked_for_leads_back() {
        let named = at("192.0.2.1:80").named(Some(Arc::from("box.example")));
        assert_eq!(
            named.path_of("http://BOX.example./login").as_deref(),
            Some("/login")
        );
        assert_eq!(
            named.path_of("http://192.0.2.1/login").as_deref(),
            Some("/login")
        );
        assert_eq!(named.path_of("http://dev.box.example/"), None);
        assert_eq!(at("192.0.2.1:80").path_of("http://box.example/"), None);
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
