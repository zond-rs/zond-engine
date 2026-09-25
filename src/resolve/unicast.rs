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
        Self {
            global: config.global.and_then(|(conf, opts)| build(conf, opts)),
            unconfigured: Once::new(),
        }
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
