// Copyright (c) 2026 Erik Lening (hollowpointer) and Contributors
//
// This file is part of Zond Engine, licensed under the GNU Affero General
// Public License, version 3 or later. See the LICENSE file for details, or
// <https://www.gnu.org/licenses/agpl-3.0.html>.
//
// SPDX-License-Identifier: AGPL-3.0-or-later

//! # Unicast DNS, as the host has it configured
//!
//! Which server a name is asked of, and whether any is.
//!
//! ## Read per pass
//!
//! A [`Unicast`] is built from the configuration as it is at one moment and
//! lives for one resolution pass. A front end that runs for hours sees the VPN
//! it connected in the meantime, and nothing it was told is kept past the pass:
//! a name that did not resolve is asked again next time, rather than answered
//! from a cache of failures while the box it names comes up.

use std::net::IpAddr;
use std::sync::Once;

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use crate::{info, warn};

/// The unicast configuration as read, before anything is built from it.
pub(crate) struct DnsConfig {
    /// The configuration names are asked under, or why the host has none.
    pub(crate) global: Result<(ResolverConfig, ResolverOpts), String>,
}

impl DnsConfig {
    /// The host's configuration, as the OS resolves with it now.
    pub(crate) fn read_system() -> Self {
        let global = hickory_resolver::system_conf::read_system_conf().map_err(|e| e.to_string());
        Self { global }
    }
}

/// Unicast DNS ready to ask, for the length of one resolution pass.
pub(crate) struct Unicast {
    /// The client names are asked of, or why there is none.
    global: Result<TokioResolver, String>,
    /// The global configuration's own domain and search list, folded, which
    /// say what the global servers are expected to answer for.
    searched: Vec<String>,
    /// Says once per pass that names needing DNS were not asked, rather than
    /// once per name.
    unconfigured: Once,
}

impl Unicast {
    /// Builds the client for the configured servers.
    ///
    /// The hosts file is not given to it: the resolver answers from it before
    /// the client is asked, so a client consulting it again could only ask
    /// upstream for the family the file did not list.
    pub(crate) fn from_config(config: DnsConfig) -> Self {
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

        Self {
            global,
            searched,
            unconfigured: Once::new(),
        }
    }

    /// Whether a configured unicast server is expected to answer for `name`:
    /// the global configuration's own domain or search list covers it.
    ///
    /// What decides whether a `.local` name is asked of unicast DNS at all. An
    /// Active Directory domain named `corp.local` is served by its domain
    /// controller, and a host joined to it carries the domain in its search
    /// list; a `.local` name nothing configured claims is a multicast name,
    /// and asking a unicast server about it only tells that server what is on
    /// the link.
    pub(crate) fn claims(&self, name: &str) -> bool {
        let name = fold(name);
        self.searched.iter().any(|domain| covers(domain, &name))
    }

    /// Asks the configured servers for the A and AAAA records of `name`.
    ///
    /// Empty when the name has no records, when nothing answered, or when the
    /// host has no server to ask; the last is said once per pass, because it
    /// is the one a user can act on.
    pub(crate) async fn lookup(&self, name: &str) -> Vec<IpAddr> {
        let client = match &self.global {
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
