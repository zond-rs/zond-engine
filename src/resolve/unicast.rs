// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Unicast DNS, as the host has it configured
//!
//! Which server a name is asked of, if any. A host has a global resolver
//! configuration, and on macOS it can also have *scoped* resolvers: servers
//! that answer for one domain only, installed by a VPN's match domains,
//! Tailscale's MagicDNS, or a file under `/etc/resolver`. The OS resolves a
//! name under such a domain through that server alone. Reading only the global
//! configuration would fail to resolve every host the VPN serves, and would
//! leak each of those names to a resolver outside the VPN.
//!
//! ## Scoped resolvers
//!
//! A scoped resolver is a domain and the servers that answer for it, taken
//! from `scutil --dns`, which reports the configuration the OS resolves with,
//! `/etc/resolver` files and VPN match domains alike. A name under the longest
//! matching domain is asked of that domain's servers alone, as the OS asks it:
//! only the domain's owner can answer, and any other server would learn a
//! private name for nothing.
//!
//! A domain stays claimed when none of its servers can be asked. A link-local
//! server is reached through the interface written after it, `fe80::53%utun4`.
//! When that interface is gone, or a server or port is unreadable, the
//! domain's names fail to resolve, with a line saying why, and do not fall
//! through to the global servers. A resolver the OS lists with no servers
//! claims nothing.
//!
//! Left out are the settings that change where the OS sends a query, not which
//! server it asks: per-interface resolvers (the "for scoped queries" half,
//! which serves only a process pinned to an interface), search-order weights,
//! and reachability flags. The multicast entries for `local` and the link-local
//! reverse zones are skipped too, since the engine speaks mDNS itself.
//!
//! The report comes from running `/usr/sbin/scutil`. The dynamic store behind
//! it has no API short of linking the SystemConfiguration framework, and
//! `scutil --dns` is Apple's documented way to read it. A machine where it
//! cannot run resolves through the global configuration alone.
//!
//! Other platforms have nothing to read: Linux's split DNS lives behind the
//! `systemd-resolved` stub, which the global configuration already names.
//!
//! ## Read per pass
//!
//! A [`Unicast`] is built from the configuration at one moment and lives for
//! one resolution pass, so a long-running front end sees a VPN connected in the
//! meantime. Nothing is cached past the pass: a name that did not resolve is
//! asked again next time.

use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Once};
use std::task::{Context, Poll};
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::{DnsUdpSocket, RuntimeProvider, TokioRuntimeProvider};
use hickory_resolver::{ConnectionProvider, Resolver, TokioResolver};

use crate::{info, warn};

/// The unicast configuration as read, before anything is built from it.
pub(crate) struct DnsConfig {
    /// The configuration for names no scoped resolver answers for, or why the
    /// host has none.
    pub(crate) global: Result<(ResolverConfig, ResolverOpts), String>,
    /// The servers that answer for one domain each.
    pub(crate) scoped: Vec<ScopedServers>,
}

/// A domain and the servers the host asks for names under it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ScopedServers {
    /// Folded to lower case, without a root dot.
    pub(crate) domain: String,
    /// The servers to ask (never empty), a link-local one carrying the scope id
    /// of its interface; or why none of the listed servers can be asked, in
    /// which case the domain's names are asked of nobody.
    pub(crate) servers: Result<Vec<SocketAddr>, String>,
}

impl DnsConfig {
    /// The host's current configuration.
    pub(crate) fn read_system() -> Self {
        let global = hickory_resolver::system_conf::read_system_conf().map_err(|e| e.to_string());
        Self {
            global,
            scoped: read_scoped(),
        }
    }
}

/// Unicast DNS ready to ask, for the length of one resolution pass.
pub(crate) struct Unicast {
    /// The client for names no scoped resolver answers for, or why there is
    /// none.
    global: Result<TokioResolver, String>,
    /// The scoped domains, longest first, so the first that covers a name is
    /// the one the OS would ask.
    scoped: Vec<Scope>,
    /// The global configuration's own domain and search list, folded, which
    /// say what the global servers are expected to answer for.
    searched: Vec<String>,
    /// Says once per pass, not once per name, that names needing DNS were not
    /// asked.
    unconfigured: Once,
}

impl Unicast {
    /// Builds a client per configured server set.
    ///
    /// The hosts file is withheld from the clients: the resolver answers from it
    /// first, and a client consulting it again would ask upstream for the
    /// family the file did not list.
    pub(crate) fn from_config(config: DnsConfig) -> Self {
        let base_opts = config
            .global
            .as_ref()
            .map_or_else(|_| ResolverOpts::default(), |(_, opts)| opts.clone());

        let (global, searched) = match config.global {
            Ok((conf, opts)) => {
                let searched = conf
                    .domain()
                    .into_iter()
                    .chain(conf.search())
                    .map(|name| fold(&name.to_ascii()))
                    .collect();
                (build(conf, opts, TokioRuntimeProvider::default()), searched)
            }
            Err(e) => (Err(e), Vec::new()),
        };

        let mut scoped: Vec<Scope> = config
            .scoped
            .into_iter()
            .map(|scope| {
                let client = scope.servers.and_then(|servers| {
                    let runtime = ZonedRuntime::for_servers(&servers);
                    let servers = servers.iter().map(|at| {
                        let mut server = NameServerConfig::udp_and_tcp(at.ip());
                        for connection in &mut server.connections {
                            connection.port = at.port();
                        }
                        server
                    });
                    let conf = ResolverConfig::from_parts(None, Vec::new(), servers.collect());
                    build(conf, base_opts.clone(), runtime)
                });
                Scope {
                    domain: scope.domain,
                    client,
                    unasked: Once::new(),
                }
            })
            .collect();
        // Stable, so of two resolvers for one domain the one the OS lists first
        // is asked.
        scoped.sort_by_key(|scope| std::cmp::Reverse(scope.domain.len()));

        Self {
            global,
            scoped,
            searched,
            unconfigured: Once::new(),
        }
    }

    /// Whether a configured unicast server is expected to answer for `name`: a
    /// scoped resolver's domain covers it, or the global configuration's own
    /// domain or search list does.
    ///
    /// Decides whether a `.local` name is asked of unicast DNS at all. An
    /// Active Directory domain named `corp.local` is served by its domain
    /// controller, and a host joined to it carries the domain in its search
    /// list. A `.local` name nothing configured claims is a multicast name.
    pub(crate) fn claims(&self, name: &str) -> bool {
        let name = fold(name);
        self.scoped.iter().any(|scope| covers(&scope.domain, &name))
            || self.searched.iter().any(|domain| covers(domain, &name))
    }

    /// Asks the server that answers for `name` for its A and AAAA records.
    ///
    /// Empty when the name has no records, when nothing answered, or when the
    /// host has no server to ask. The last is warned once per pass and domain,
    /// since a user can act on it.
    pub(crate) async fn lookup(&self, name: &str) -> Vec<IpAddr> {
        let folded = fold(name);
        if let Some(scope) = self
            .scoped
            .iter()
            .find(|scope| covers(&scope.domain, &folded))
        {
            return match &scope.client {
                Ok(client) => ask(client, name).await,
                Err(why) => {
                    scope
                        .unasked
                        .call_once(|| warn!("DNS for {} not asked ({why})", scope.domain));
                    Vec::new()
                }
            };
        }
        let client = match &self.global {
            Ok(client) => client,
            Err(why) => {
                self.say_unconfigured(why);
                return Vec::new();
            }
        };
        ask(client, name).await
    }

    /// Asks the server that answers for `ip`'s reverse zone for its PTR
    /// record.
    ///
    /// Routed as [`lookup`](Self::lookup) routes a name, by the name the
    /// question carries. A VPN that serves the reverse zone of its addresses
    /// installs a scoped resolver for, say, `16.172.in-addr.arpa`, and a PTR
    /// asked of the global servers would fail and tell them which private
    /// address the scan found. A missing configuration is warned once per pass,
    /// shared with `lookup`.
    pub(crate) async fn reverse(&self, ip: IpAddr) -> Reverse {
        if let Some(scope) = self.reverse_scope(ip).map(|index| &self.scoped[index]) {
            return match &scope.client {
                Ok(client) => ask_reverse(client, ip).await,
                Err(why) => {
                    scope
                        .unasked
                        .call_once(|| warn!("DNS for {} not asked ({why})", scope.domain));
                    Reverse::Unasked
                }
            };
        }
        match &self.global {
            Ok(client) => ask_reverse(client, ip).await,
            Err(why) => {
                self.say_unconfigured(why);
                Reverse::Unasked
            }
        }
    }

    /// Which scoped resolver [`reverse`](Self::reverse) asks about `ip`, by
    /// its place among them, or `None` for the global ones.
    pub(crate) fn reverse_scope(&self, ip: IpAddr) -> Option<usize> {
        let name = reverse_name(ip);
        self.scoped
            .iter()
            .position(|scope| covers(&scope.domain, &name))
    }

    /// Says, once per pass, that the host has no server for a name no scoped
    /// resolver answers for.
    fn say_unconfigured(&self, why: &str) {
        self.unconfigured.call_once(|| {
            warn!("DNS lookups skipped (no DNS server configured)");
            info!(
                verbosity = 1,
                "system resolver configuration unusable: {why}"
            );
        });
    }
}

/// What a reverse lookup of one address came back with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Reverse {
    /// The name the hosts file gives the address; nothing was asked.
    Listed(String),
    /// The name a server answered with.
    Named(String),
    /// A server answered, with no name in it.
    Unnamed,
    /// No answer at all: the server let the question time out, or could not
    /// be reached.
    Unanswered,
    /// Nobody was asked: no server answers for the address's reverse zone, or
    /// the address is one no server is asked about.
    Unasked,
}

/// Asks `client` for `ip`'s PTR record.
async fn ask_reverse<P: ConnectionProvider>(client: &Resolver<P>, ip: IpAddr) -> Reverse {
    use hickory_resolver::proto::rr::RData;

    let lookup = match client.reverse_lookup(ip).await {
        Ok(lookup) => lookup,
        // Any DNS-level error is still an answer from the server; a timeout or
        // transport failure is not.
        Err(hickory_resolver::net::NetError::Dns(_)) => return Reverse::Unnamed,
        Err(_) => return Reverse::Unanswered,
    };
    lookup
        .answers()
        .iter()
        .find_map(|record| match &record.data {
            RData::PTR(ptr) => Some(ptr.to_string()),
            _ => None,
        })
        .map_or(Reverse::Unnamed, Reverse::Named)
}

/// The name a reverse lookup of `ip` asks, folded as [`covers`] compares it:
/// `4.3.2.1.in-addr.arpa` for `1.2.3.4`, and the nibbles under `ip6.arpa` for
/// an IPv6 address.
pub(crate) fn reverse_name(ip: IpAddr) -> String {
    fold(&hickory_resolver::proto::rr::Name::from(ip).to_ascii())
}

/// A scoped domain and the client that answers for it.
struct Scope {
    /// Folded, as [`covers`] compares it.
    domain: String,
    /// The client for the domain's servers, or why none of them can be asked.
    client: Result<Resolver<ZonedRuntime>, String>,
    /// Says once per pass that the domain's names went unasked.
    unasked: Once,
}

/// Asks `client` for `name`'s A and AAAA records.
async fn ask<P: ConnectionProvider>(client: &Resolver<P>, name: &str) -> Vec<IpAddr> {
    match client.lookup_ip(name).await {
        Ok(lookup) => lookup.iter().collect(),
        // No records and a failed lookup both resolve to nothing.
        Err(_) => Vec::new(),
    }
}

/// Builds one client, with the hosts file left to the caller.
fn build<P: ConnectionProvider>(
    conf: ResolverConfig,
    mut opts: ResolverOpts,
    runtime: P,
) -> Result<Resolver<P>, String> {
    opts.use_hosts_file = ResolveHosts::Never;
    Resolver::builder_with_config(conf, runtime)
        .with_options(opts)
        .build()
        .map_err(|e| e.to_string())
}

/// The Tokio runtime, sending to each IPv6 server through the interface its
/// scope id names.
///
/// The resolver's server configuration holds a bare address, which it pairs
/// with a port into a socket address with scope id zero, and the kernel refuses
/// to send to a link-local address without a scope. This restores the scope on
/// the way out, for UDP and TCP. Replies are matched to servers by address and
/// port, so a reply arriving with its scope set still matches.
///
/// Keyed by address: of two servers at one link-local address on different
/// interfaces, the first listed is the one reached.
#[derive(Clone)]
struct ZonedRuntime {
    tokio: TokioRuntimeProvider,
    /// The scope id each IPv6 server is reached through.
    zones: Arc<[(Ipv6Addr, u32)]>,
}

impl ZonedRuntime {
    /// A runtime reaching `servers` through the interfaces their scope ids
    /// name.
    fn for_servers(servers: &[SocketAddr]) -> Self {
        let zones = servers
            .iter()
            .filter_map(|at| match at {
                SocketAddr::V6(v6) if v6.scope_id() != 0 => Some((*v6.ip(), v6.scope_id())),
                _ => None,
            })
            .collect();
        Self {
            tokio: TokioRuntimeProvider::default(),
            zones,
        }
    }

    /// `to`, with the scope id of the server at its address when it has none.
    fn zoned(zones: &[(Ipv6Addr, u32)], to: SocketAddr) -> SocketAddr {
        match to {
            SocketAddr::V6(mut v6) if v6.scope_id() == 0 => {
                if let Some((_, scope)) = zones.iter().find(|(ip, _)| ip == v6.ip()) {
                    v6.set_scope_id(*scope);
                }
                SocketAddr::V6(v6)
            }
            other => other,
        }
    }
}

impl RuntimeProvider for ZonedRuntime {
    type Handle = <TokioRuntimeProvider as RuntimeProvider>::Handle;
    type Timer = <TokioRuntimeProvider as RuntimeProvider>::Timer;
    type Udp = ZonedUdp;
    type Tcp = <TokioRuntimeProvider as RuntimeProvider>::Tcp;

    fn create_handle(&self) -> Self::Handle {
        self.tokio.create_handle()
    }

    fn connect_tcp(
        &self,
        server_addr: SocketAddr,
        bind_addr: Option<SocketAddr>,
        timeout: Option<Duration>,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Tcp, io::Error>>>> {
        let server_addr = Self::zoned(&self.zones, server_addr);
        self.tokio.connect_tcp(server_addr, bind_addr, timeout)
    }

    fn bind_udp(
        &self,
        local_addr: SocketAddr,
        server_addr: SocketAddr,
    ) -> Pin<Box<dyn Send + Future<Output = Result<Self::Udp, io::Error>>>> {
        let zones = Arc::clone(&self.zones);
        let bound = self.tokio.bind_udp(local_addr, server_addr);
        Box::pin(async move {
            Ok(ZonedUdp {
                socket: bound.await?,
                zones,
            })
        })
    }
}

/// A UDP socket that sends through the interface a server's scope id names;
/// see [`ZonedRuntime`].
struct ZonedUdp {
    socket: <TokioRuntimeProvider as RuntimeProvider>::Udp,
    zones: Arc<[(Ipv6Addr, u32)]>,
}

impl DnsUdpSocket for ZonedUdp {
    type Time = <<TokioRuntimeProvider as RuntimeProvider>::Udp as DnsUdpSocket>::Time;

    fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<(usize, SocketAddr)>> {
        DnsUdpSocket::poll_recv_from(&self.socket, cx, buf)
    }

    fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<io::Result<usize>> {
        let target = ZonedRuntime::zoned(&self.zones, target);
        DnsUdpSocket::poll_send_to(&self.socket, cx, buf, target)
    }
}

/// Whether `domain` is `name` or one of its ancestors, label by label.
pub(crate) fn covers(domain: &str, name: &str) -> bool {
    !domain.is_empty()
        && (name == domain
            || name
                .strip_suffix(domain)
                .is_some_and(|host| host.ends_with('.')))
}

/// A name folded for comparison: lower case, no root dot.
fn fold(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

/// The host's scoped resolvers; see the module documentation for which.
#[cfg(target_vendor = "apple")]
fn read_scoped() -> Vec<ScopedServers> {
    match std::process::Command::new("/usr/sbin/scutil")
        .arg("--dns")
        .output()
    {
        Ok(out) if out.status.success() => {
            parse_scutil_dns(&String::from_utf8_lossy(&out.stdout), interface_index)
        }
        Ok(out) => {
            info!(
                verbosity = 1,
                "scoped resolvers not read (scutil: {})", out.status
            );
            Vec::new()
        }
        Err(e) => {
            info!(verbosity = 1, "scoped resolvers not read (scutil: {e})");
            Vec::new()
        }
    }
}

/// The index of the interface named `name`, if the host has one.
#[cfg(target_vendor = "apple")]
fn interface_index(name: &str) -> Option<u32> {
    let name = std::ffi::CString::new(name).ok()?;
    // SAFETY: `name` is a valid NUL-terminated string for the whole call.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    (index != 0).then_some(index)
}

/// No platform but macOS has scoped resolvers to read.
#[cfg(not(target_vendor = "apple"))]
fn read_scoped() -> Vec<ScopedServers> {
    Vec::new()
}

/// The scoped resolvers in a `scutil --dns` report: every resolver in its
/// first section with a domain, at least one server, and no `mdns` option.
///
/// The first section is the configuration every process resolves with; the
/// second, "for scoped queries", serves only a process bound to one interface.
///
/// A link-local server is written with its interface, `fe80::53%utun4`, which
/// `index_of` turns into a scope id. A resolver keeps its domain whatever its
/// servers turn out to be. A server whose interface `index_of` does not know,
/// an unreadable server or port, or a link-local server with no interface is
/// not asked, and a resolver left with none to ask carries the reason, so its
/// names fail and do not reach the global servers.
#[cfg(any(target_vendor = "apple", test))]
fn parse_scutil_dns(report: &str, index_of: impl Fn(&str) -> Option<u32>) -> Vec<ScopedServers> {
    /// The port DNS is asked on when a resolver names none.
    const DNS_PORT: u16 = 53;

    #[derive(Default)]
    struct Entry {
        domain: Option<String>,
        /// Each listed server as an address and scope id, or why it cannot be
        /// asked.
        servers: Vec<Result<(IpAddr, u32), String>>,
        /// The port a resolver names, or why the one it names does not read.
        port: Option<Result<u16, String>>,
        mdns: bool,
    }

    fn finish(entry: Entry, into: &mut Vec<ScopedServers>) {
        let Some(domain) = entry.domain else { return };
        if entry.mdns || entry.servers.is_empty() {
            return;
        }
        let servers = entry.port.unwrap_or(Ok(DNS_PORT)).and_then(|port| {
            let (usable, unusable): (Vec<_>, Vec<_>) =
                entry.servers.into_iter().partition(Result::is_ok);
            let usable: Vec<SocketAddr> = usable
                .into_iter()
                .flatten()
                .map(|(ip, scope)| match ip {
                    IpAddr::V4(v4) => SocketAddr::new(v4.into(), port),
                    IpAddr::V6(v6) => std::net::SocketAddrV6::new(v6, port, 0, scope).into(),
                })
                .collect();
            match unusable.into_iter().find_map(Result::err) {
                Some(why) if usable.is_empty() => Err(why),
                _ => Ok(usable),
            }
        });
        into.push(ScopedServers { domain, servers });
    }

    /// A `nameserver` value as an address and the scope id it is asked with.
    fn server(
        value: &str,
        index_of: &impl Fn(&str) -> Option<u32>,
    ) -> Result<(IpAddr, u32), String> {
        let (address, zone) = match value.split_once('%') {
            Some((address, zone)) => (address, Some(zone)),
            None => (value, None),
        };
        let unreadable = || format!("server {value} unreadable");
        match (address.parse().map_err(|_| unreadable())?, zone) {
            (ip @ IpAddr::V6(_), Some(zone)) => index_of(zone)
                .filter(|&index| index != 0)
                .map(|index| (ip, index))
                .ok_or_else(|| format!("{zone} not found")),
            (IpAddr::V4(_), Some(_)) => Err(unreadable()),
            (IpAddr::V6(v6), None) if v6.is_unicast_link_local() => {
                Err(format!("server {value} has no interface"))
            }
            (ip, None) => Ok((ip, 0)),
        }
    }

    let mut found = Vec::new();
    let mut entry: Option<Entry> = None;
    for line in report.lines() {
        let line = line.trim();
        if line.starts_with("DNS configuration (") {
            break;
        }
        if line.starts_with("resolver #") {
            if let Some(done) = entry.replace(Entry::default()) {
                finish(done, &mut found);
            }
            continue;
        }
        let (Some(current), Some((key, value))) = (entry.as_mut(), line.split_once(':')) else {
            continue;
        };
        let (key, value) = (key.trim(), value.trim());
        match key {
            "domain" => current.domain = Some(fold(value)).filter(|d| !d.is_empty()),
            "port" => {
                current.port = Some(
                    value
                        .parse()
                        .ok()
                        .filter(|&port| port != 0)
                        .ok_or_else(|| format!("port {value} unreadable")),
                );
            }
            "options" => current.mdns |= value.split_whitespace().any(|o| o == "mdns"),
            _ if key.starts_with("nameserver[") => current.servers.push(server(value, &index_of)),
            _ => {}
        }
    }
    if let Some(done) = entry {
        finish(done, &mut found);
    }
    found
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
    use crate::logging::logged;

    /// A `scutil --dns` report as a Mac with a VPN and a resolver file prints
    /// it, reduced to what the parser reads.
    const REPORT: &str = "\
DNS configuration

resolver #1
  search domain[0] : home.example
  nameserver[0] : 192.0.2.1
  if_index : 15 (en1)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : Corp.Example.
  nameserver[0] : 198.51.100.53
  nameserver[1] : fe80::53%utun4
  nameserver[2] : 2001:db8::53
  flags    : Supplemental, Request A records, Request AAAA records
  order    : 102400

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
  order    : 300000

resolver #4
  domain   : lab.example
  nameserver[0] : 203.0.113.53
  port     : 5353

resolver #5
  domain   : nothing-to-ask.example

DNS configuration (for scoped queries)

resolver #1
  domain   : scoped-only.example
  nameserver[0] : 192.0.2.99
  if_index : 15 (en1)
";

    /// The interface index a test host gives `utun4`, and no other name.
    fn utun4_is_9(name: &str) -> Option<u32> {
        (name == "utun4").then_some(9)
    }

    /// The report yields the domain-bound servers the OS asks, a link-local
    /// one with the scope id of its interface, and nothing that is multicast,
    /// serverless, the default resolver, or bound to one interface.
    #[test]
    fn a_scutil_report_yields_the_domains_with_servers_of_their_own() {
        let at = |s: &str| s.parse::<SocketAddr>().expect("a socket address");
        assert_eq!(
            parse_scutil_dns(REPORT, utun4_is_9),
            vec![
                ScopedServers {
                    domain: "corp.example".into(),
                    servers: Ok(vec![
                        at("198.51.100.53:53"),
                        at("[fe80::53%9]:53"),
                        at("[2001:db8::53]:53"),
                    ]),
                },
                ScopedServers {
                    domain: "lab.example".into(),
                    servers: Ok(vec![at("203.0.113.53:5353")]),
                },
            ]
        );
    }

    /// A VPN's match domain whose one server is link-local, written with the
    /// interface it is reached through.
    const ZONED_REPORT: &str = "\
DNS configuration

resolver #1
  domain   : vpn.example
  nameserver[0] : fe80::53%utun4
";

    /// A global configuration naming `at`, giving up on a silent server fast.
    fn global_at(at: SocketAddr) -> (ResolverConfig, ResolverOpts) {
        let mut server = NameServerConfig::udp(at.ip());
        for connection in &mut server.connections {
            connection.port = at.port();
        }
        let mut opts = ResolverOpts::default();
        opts.attempts = 1;
        opts.timeout = std::time::Duration::from_millis(200);
        (
            ResolverConfig::from_parts(None, Vec::new(), vec![server]),
            opts,
        )
    }

    /// A domain whose only server is link-local keeps that server, with the
    /// scope id of the interface it is reached through, and claims its names.
    ///
    /// VPNs and Tailscale hand out DNS servers on their own interfaces. Losing
    /// the resolver because its server carries a zone would send every private
    /// name to the resolver outside.
    #[test]
    fn a_domain_whose_only_server_is_link_local_keeps_it_with_its_scope() {
        let scoped = parse_scutil_dns(ZONED_REPORT, utun4_is_9);
        assert_eq!(
            scoped,
            vec![ScopedServers {
                domain: "vpn.example".into(),
                servers: Ok(vec!["[fe80::53%9]:53".parse().expect("an address")]),
            }]
        );

        let unicast = Unicast::from_config(DnsConfig {
            global: Err("none configured".into()),
            scoped,
        });
        assert!(unicast.claims("intranet.vpn.example"));
    }

    /// A name under a domain whose link-local server's interface is gone is
    /// asked of nobody, and the global server never hears it; the user is told
    /// once per pass which domain went unasked and why.
    ///
    /// A VPN that dropped its tunnel leaves its resolver behind for a moment,
    /// and sending its names to the global server then would leak them.
    #[test]
    fn a_domain_whose_server_interface_is_gone_is_never_asked_of_the_global_server() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a runtime builds");
        let global = crate::testing::loopback::SilentUdpPort::open();
        let unicast = Unicast::from_config(DnsConfig {
            global: Ok(global_at(global.addr())),
            scoped: parse_scutil_dns(ZONED_REPORT, |_| None),
        });

        assert!(unicast.claims("intranet.vpn.example"));
        let mut resolved = Vec::new();
        let lines = logged(|| {
            runtime.block_on(async {
                for name in ["intranet.vpn.example", "wiki.vpn.example"] {
                    resolved.extend(unicast.lookup(name).await);
                }
            });
        });

        assert_eq!(resolved, Vec::<IpAddr>::new());
        assert!(
            global.datagrams().is_empty(),
            "the VPN name reached the global server"
        );
        let said: Vec<_> = lines
            .iter()
            .filter(|l| l.verbosity == 0 && l.message.contains("vpn.example"))
            .map(|l| l.message.as_str())
            .collect();
        assert_eq!(said, ["DNS for vpn.example not asked (utun4 not found)"]);
    }

    /// A resolver whose servers or port do not read keeps its domain, with
    /// why none of its servers can be asked, and one with a server that reads
    /// is asked through it alone.
    ///
    /// Dropping the resolver would hand its domain to the global servers, and
    /// asking an unreadable port's server on 53 would ask a port the host never
    /// named.
    #[test]
    fn a_resolver_whose_servers_do_not_read_keeps_its_domain() {
        let report = "\
DNS configuration

resolver #1
  domain   : port.example
  nameserver[0] : 198.51.100.53
  port     : domain

resolver #2
  domain   : garbled.example
  nameserver[0] : 198.51.100.53:53

resolver #3
  domain   : zoneless.example
  nameserver[0] : fe80::53

resolver #4
  domain   : zoned-v4.example
  nameserver[0] : 198.51.100.53%utun4

resolver #5
  domain   : mixed.example
  nameserver[0] : fe80::53%utun9
  nameserver[1] : 2001:db8::53
";
        let unasked = |domain: &str, why: &str| ScopedServers {
            domain: domain.into(),
            servers: Err(why.into()),
        };
        assert_eq!(
            parse_scutil_dns(report, utun4_is_9),
            vec![
                unasked("port.example", "port domain unreadable"),
                unasked("garbled.example", "server 198.51.100.53:53 unreadable"),
                unasked("zoneless.example", "server fe80::53 has no interface"),
                unasked("zoned-v4.example", "server 198.51.100.53%utun4 unreadable"),
                ScopedServers {
                    domain: "mixed.example".into(),
                    servers: Ok(vec!["[2001:db8::53]:53".parse().expect("an address")]),
                },
            ]
        );
    }

    /// The runtime puts a server's scope id on an address that lost it, and
    /// leaves every other address as it was.
    ///
    /// The resolver hands the runtime a link-local server with a scope id of
    /// zero, which the kernel will not send to.
    #[test]
    fn the_runtime_sends_to_a_link_local_server_through_its_interface() {
        let at = |s: &str| s.parse::<SocketAddr>().expect("a socket address");
        let runtime = ZonedRuntime::for_servers(&[at("[fe80::53%9]:53"), at("192.0.2.53:53")]);

        assert_eq!(
            ZonedRuntime::zoned(&runtime.zones, at("[fe80::53]:53")),
            at("[fe80::53%9]:53")
        );
        for untouched in ["[fe80::53%4]:53", "[fe80::54]:53", "192.0.2.53:53"] {
            assert_eq!(
                ZonedRuntime::zoned(&runtime.zones, at(untouched)),
                at(untouched)
            );
        }
    }

    /// A domain covers itself and its descendants, whole labels only, so
    /// `notcorp.example` is not asked of `corp.example`'s server.
    #[test]
    fn a_domain_covers_itself_and_the_names_under_it_and_nothing_else() {
        assert!(covers("corp.example", "corp.example"));
        assert!(covers("corp.example", "dc01.corp.example"));
        assert!(!covers("corp.example", "notcorp.example"));
        assert!(!covers("corp.example", "example"));
        assert!(!covers("", "example"));
    }
}
