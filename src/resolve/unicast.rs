// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Unicast DNS, as the host has it configured
//!
//! Which server a name is asked of, and whether any is. A host has a global
//! resolver configuration, and on macOS it can also have *scoped* resolvers: a
//! server that answers for one domain only, installed by a VPN's match domains,
//! by Tailscale's MagicDNS, or by a file under `/etc/resolver`. A name under
//! such a domain is resolved by the OS through that server and no other, so a
//! scanner that read the global configuration alone would fail to resolve every
//! host the VPN serves while the OS resolves it fine, and would send each of
//! those names to a resolver outside the VPN on its way to failing.
//!
//! ## How far scoped resolvers are followed
//!
//! A scoped resolver here is a domain and the servers that answer for it,
//! taken from `scutil --dns`, which reports the configuration the OS resolves
//! with, `/etc/resolver` files and VPN match domains alike. A name under the
//! longest such domain is asked of that domain's servers alone, as the OS asks
//! it, never also of the global ones: the domain's owner is the only server
//! that can answer, and any other would learn a name inside a private network
//! for nothing.
//!
//! What is left out is what changes *where* the OS sends a query rather than
//! *which* server it asks: per-interface resolvers (the "for scoped queries"
//! half, which serves only a process that pinned itself to an interface),
//! search-order weights, and reachability flags. The multicast entries the OS
//! lists for `local` and the link-local reverse zones are left out too, since
//! the engine speaks mDNS itself.
//!
//! The report comes from running `/usr/sbin/scutil`. The dynamic store behind
//! it has no API short of linking the SystemConfiguration framework by hand,
//! and `scutil --dns` is the interface Apple documents for reading it. A
//! machine where it cannot run resolves through the global configuration
//! alone.
//!
//! Elsewhere there is nothing to read: Linux's split DNS lives behind
//! `systemd-resolved`'s stub, which the global configuration already names,
//! so a name reaches the right server by asking the one listed.
//!
//! ## Read per pass
//!
//! A [`Unicast`] is built from the configuration as it is at one moment and
//! lives for one resolution pass. A front end that runs for hours sees the VPN
//! it connected in the meantime, and nothing it was told is kept past the pass:
//! a name that did not resolve is asked again next time, rather than answered
//! from a cache of failures while the box it names comes up.

use std::net::{IpAddr, SocketAddr};
use std::sync::Once;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

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
    pub(crate) servers: Vec<SocketAddr>,
}

impl DnsConfig {
    /// The host's configuration, as the OS resolves with it now.
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
    /// A client per scoped domain, longest domain first, so the first that
    /// covers a name is the one the OS would ask.
    scoped: Vec<(String, TokioResolver)>,
    /// The global configuration's own domain and search list, folded, which
    /// say what the global servers are expected to answer for.
    searched: Vec<String>,
    /// Says once per pass that names needing DNS were not asked, rather than
    /// once per name.
    unconfigured: Once,
}

impl Unicast {
    /// Builds a client per configured server set.
    ///
    /// The hosts file is not given to any of them: the resolver answers from
    /// it before a client is asked, so a client consulting it again could only
    /// ask upstream for the family the file did not list.
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
                (build(conf, opts), searched)
            }
            Err(e) => (Err(e), Vec::new()),
        };

        let mut scoped: Vec<(String, TokioResolver)> = config
            .scoped
            .into_iter()
            .filter_map(|scope| {
                let servers = scope.servers.iter().map(|at| {
                    let mut server = NameServerConfig::udp_and_tcp(at.ip());
                    for connection in &mut server.connections {
                        connection.port = at.port();
                    }
                    server
                });
                let conf = ResolverConfig::from_parts(None, Vec::new(), servers.collect());
                match build(conf, base_opts.clone()) {
                    Ok(client) => Some((scope.domain, client)),
                    Err(e) => {
                        warn!("DNS for {} not asked ({e})", scope.domain);
                        None
                    }
                }
            })
            .collect();
        // Stable, so of two resolvers for one domain the one listed first,
        // which the OS orders first, is the one asked.
        scoped.sort_by_key(|(domain, _)| std::cmp::Reverse(domain.len()));

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
    /// What decides whether a `.local` name is asked of unicast DNS at all. An
    /// Active Directory domain named `corp.local` is served by its domain
    /// controller, and a host joined to it carries the domain in its search
    /// list; a `.local` name nothing configured claims is a multicast name,
    /// and asking a unicast server about it only tells that server what is on
    /// the link.
    pub(crate) fn claims(&self, name: &str) -> bool {
        let name = fold(name);
        self.scoped.iter().any(|(domain, _)| covers(domain, &name))
            || self.searched.iter().any(|domain| covers(domain, &name))
    }

    /// Asks the server that answers for `name` for its A and AAAA records.
    ///
    /// Empty when the name has no records, when nothing answered, or when the
    /// host has no server to ask; the last is said once per pass, because it
    /// is the one a user can act on.
    pub(crate) async fn lookup(&self, name: &str) -> Vec<IpAddr> {
        let folded = fold(name);
        let client = match self
            .scoped
            .iter()
            .find(|(domain, _)| covers(domain, &folded))
        {
            Some((_, client)) => client,
            None => match &self.global {
                Ok(client) => client,
                Err(why) => {
                    self.unconfigured.call_once(|| {
                        warn!("DNS lookups skipped (no DNS server configured)");
                        info!(
                            verbosity = 1,
                            "system resolver configuration unusable: {why}"
                        );
                    });
                    return Vec::new();
                }
            },
        };

        match client.lookup_ip(name).await {
            Ok(lookup) => lookup.iter().collect(),
            // A name with no records is an ordinary answer, not a failure worth
            // surfacing: it resolves to nothing, which is what an empty vector
            // says.
            Err(_) => Vec::new(),
        }
    }
}

/// Builds one client, with the hosts file left to the caller.
fn build(conf: ResolverConfig, mut opts: ResolverOpts) -> Result<TokioResolver, String> {
    opts.use_hosts_file = ResolveHosts::Never;
    TokioResolver::builder_with_config(conf, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| e.to_string())
}

/// Whether `domain` is `name` or one of its ancestors, label by label.
fn covers(domain: &str, name: &str) -> bool {
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
        Ok(out) if out.status.success() => parse_scutil_dns(&String::from_utf8_lossy(&out.stdout)),
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
/// A server that does not parse as an address, such as a link-local one with
/// its zone written after it, is skipped, and a resolver left with none is too.
#[cfg(any(target_vendor = "apple", test))]
fn parse_scutil_dns(report: &str) -> Vec<ScopedServers> {
    /// The port DNS is asked on when a resolver names none.
    const DNS_PORT: u16 = 53;

    #[derive(Default)]
    struct Entry {
        domain: Option<String>,
        servers: Vec<IpAddr>,
        port: Option<u16>,
        mdns: bool,
    }

    fn finish(entry: Entry, into: &mut Vec<ScopedServers>) {
        let Some(domain) = entry.domain else { return };
        if entry.mdns || entry.servers.is_empty() {
            return;
        }
        let port = entry.port.unwrap_or(DNS_PORT);
        let servers = entry
            .servers
            .into_iter()
            .map(|ip| SocketAddr::new(ip, port))
            .collect();
        into.push(ScopedServers { domain, servers });
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
            "port" => current.port = value.parse().ok(),
            "options" => current.mdns |= value.split_whitespace().any(|o| o == "mdns"),
            _ if key.starts_with("nameserver[") => {
                if let Ok(ip) = value.parse() {
                    current.servers.push(ip);
                }
            }
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

    /// The report yields the domain-bound servers the OS asks, and nothing
    /// that is multicast, serverless, the default resolver, or bound to one
    /// interface. A resolver taken from the wrong half, or an mDNS entry taken
    /// as unicast, would send names to a server the OS never asks about them.
    #[test]
    fn a_scutil_report_yields_the_domains_with_servers_of_their_own() {
        let v4 = |s: &str, port| SocketAddr::new(s.parse().expect("an address"), port);
        assert_eq!(
            parse_scutil_dns(REPORT),
            vec![
                ScopedServers {
                    domain: "corp.example".into(),
                    servers: vec![v4("198.51.100.53", 53), v4("2001:db8::53", 53)],
                },
                ScopedServers {
                    domain: "lab.example".into(),
                    servers: vec![v4("203.0.113.53", 5353)],
                },
            ]
        );
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
